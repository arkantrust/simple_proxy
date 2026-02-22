package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Simple production-grade forward proxy supporting:
// - HTTP proxying
// - HTTPS via CONNECT tunneling (no MITM)
// - Optional Basic Auth
// - ACLs to allow/deny destinations (CIDR allowlist + private-network blocking)
// - Port allowlist (sane defaults)
// - Structured logging
// - Timeouts, keep-alives, graceful shutdown

// Usage:
//   go run ./main.go \
//     -listen 192.168.10.1:8080 \
//     -user proxyuser -pass proxypass \
//     -allow-cidr 0.0.0.0/0,::/0 \
//     -deny-private=true
//
// Clients (browsers/OS) should configure an HTTP proxy at the listen address.

// ---------- Flags ----------
var (
	listenAddr   = flag.String("listen", "0.0.0.0:8080", "interface:port to listen on (bind to your lab-side eth0 IP)")
	user         = flag.String("user", "", "optional Basic Auth username")
	pass         = flag.String("pass", "", "optional Basic Auth password")
	allowCIDRs   = flag.String("allow-cidr", "0.0.0.0/0,::/0", "comma-separated CIDR list of destination IPs allowed")
	denyPrivate  = flag.Bool("deny-private", true, "block RFC1918/ULA destinations for CONNECT and HTTP requests")
	allowPorts   = flag.String("allow-ports", "80,443,8080,8443", "comma-separated list of destination TCP ports allowed")
	idleTimeout  = flag.Duration("idle-timeout", 90*time.Second, "idle timeout for client and upstream connections")
	dialTimeout  = flag.Duration("dial-timeout", 10*time.Second, "timeout for dialing upstream hosts")
	readTimeout  = flag.Duration("read-timeout", 0, "server read timeout (0 = disabled)")
	writeTimeout = flag.Duration("write-timeout", 0, "server write timeout (0 = disabled)")
	verbose      = flag.Bool("v", true, "verbose logging")
)

// ---------- ACL helpers ----------

type acl struct {
	allow []netip.Prefix
	denyPrivate bool
	allowedPorts map[int]struct{}
}

func newACL(cidrs string, denyPrivate bool, ports string) (*acl, error) {
	ac := &acl{denyPrivate: denyPrivate, allowedPorts: map[int]struct{}{}}
	for _, p := range strings.Split(ports, ",") {
		p = strings.TrimSpace(p)
		if p == "" { continue }
		var port int
		_, err := fmt.Sscanf(p, "%d", &port)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port: %q", p)
		}
		ac.allowedPorts[port] = struct{}{}
	}
	for _, c := range strings.Split(cidrs, ",") {
		c = strings.TrimSpace(c)
		if c == "" { continue }
		pfx, err := netip.ParsePrefix(c)
		if err != nil { return nil, fmt.Errorf("invalid CIDR %q: %w", c, err) }
		ac.allow = append(ac.allow, pfx)
	}
	return ac, nil
}

func (a *acl) portAllowed(port int) bool {
	_, ok := a.allowedPorts[port]
	return ok
}

func (a *acl) ipAllowed(ip netip.Addr) bool {
	if a.denyPrivate {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			return false
		}
	}
	for _, p := range a.allow {
		if p.Contains(ip) { return true }
	}
	return false
}

// ---------- Auth ----------

func checkBasicAuth(r *http.Request, wantUser, wantPass string) bool {
	if wantUser == "" && wantPass == "" { return true }
	u, p, ok := r.BasicAuth()
	return ok && u == wantUser && p == wantPass
}

// ---------- Utilities ----------

var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade",
}

func stripHopByHop(h http.Header) {
	for _, k := range hopByHopHeaders { h.Del(k) }
	// Also respect Connection header tokens
	for _, tok := range h["Connection"] {
		for _, f := range strings.Split(tok, ",") {
			if f = strings.TrimSpace(f); f != "" { h.Del(f) }
		}
	}
}

// ---------- Proxy ----------

type proxy struct {
	acl *acl
	transport *http.Transport
	authUser string
	authPass string
	idle time.Duration
}

func newProxy(ac *acl, dialTO, idle time.Duration, authUser, authPass string) *proxy {
	dialer := &net.Dialer{ Timeout: dialTO, KeepAlive: 30 * time.Second }
	tr := &http.Transport{
		Proxy: nil, // do not chain
		DialContext: dialer.DialContext,
		ForceAttemptHTTP2: true,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns: 200,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout: 90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &proxy{acl: ac, transport: tr, authUser: authUser, authPass: authPass, idle: idle}
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if !checkBasicAuth(r, p.authUser, p.authPass) {
		w.Header().Set("Proxy-Authenticate", "Basic realm=proxy")
		http.Error(w, "proxy auth required", http.StatusProxyAuthRequired)
		return
	}

	// Enforce idle deadline on client conn, if we can get it
	if cn, ok := w.(http.Hijacker); ok {
		// We will re-wrap for CONNECT; for normal HTTP path we let net/http manage it.
		_ = cn
	}

	switch r.Method {
	case http.MethodConnect:
		p.handleConnect(w, r)
	default:
		p.handleHTTP(w, r)
	}
	if *verbose {
		log.Printf("%s %s from %s in %v", r.Method, r.Host, clientAddr(r), time.Since(start))
	}
}

func clientAddr(r *http.Request) string {
	if ra, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		_ = ra
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" { return xff }
	if ra := r.RemoteAddr; ra != "" { return ra }
	return "?"
}

func (p *proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Must be absolute-form URL for proxies; most clients do this when a proxy is configured.
	if !r.URL.IsAbs() {
		http.Error(w, "absolute URL required", http.StatusBadRequest)
		return
	}

	// ACL: resolve host → IP, check IP + port
	host, portStr, err := net.SplitHostPort(r.URL.Host)
	if err != nil {
		// maybe no port in URL (default by scheme)
		host = r.URL.Host
		if r.URL.Scheme == "https" { portStr = "443" } else { portStr = "80" }
	}
	port, _ := parsePort(portStr)
	if !p.acl.portAllowed(port) {
		http.Error(w, "destination port not allowed", http.StatusForbidden)
		return
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		http.Error(w, "DNS resolution failed", http.StatusBadGateway)
		return
	}
	allowed := false
	for _, ip := range ips {
		if p.acl.ipAllowed(toAddr(ip)) { allowed = true; break }
	}
	if !allowed {
		http.Error(w, "destination not allowed by ACL", http.StatusForbidden)
		return
	}

	// Prepare upstream request
	outReq := r.Clone(context.Background())
	outReq.RequestURI = "" // required by net/http
	stripHopByHop(outReq.Header)

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header { for _, v := range vv { w.Header().Add(k, v) } }
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// r.Host is like "example.com:443"
	host, portStr, err := net.SplitHostPort(r.Host)
	if err != nil { http.Error(w, "bad CONNECT host", http.StatusBadRequest); return }
	port, err := parsePort(portStr)
	if err != nil || !p.acl.portAllowed(port) { http.Error(w, "port not allowed", http.StatusForbidden); return }

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 { http.Error(w, "DNS resolution failed", http.StatusBadGateway); return }
	allowed := false
	for _, ip := range ips { if p.acl.ipAllowed(toAddr(ip)) { allowed = true; break } }
	if !allowed { http.Error(w, "destination not allowed by ACL", http.StatusForbidden); return }

	// Dial upstream
	ctx, cancel := context.WithTimeout(r.Context(), *dialTimeout)
	defer cancel()
	upConn, err := (&net.Dialer{Timeout: *dialTimeout}).DialContext(ctx, "tcp", r.Host)
	if err != nil { http.Error(w, "connect upstream failed", http.StatusBadGateway); return }

	// Hijack client connection
	hj, ok := w.(http.Hijacker)
	if !ok { http.Error(w, "hijacking not supported", http.StatusInternalServerError); _ = upConn.Close(); return }
	clientConn, buf, err := hj.Hijack()
	if err != nil { http.Error(w, "hijack failed", http.StatusInternalServerError); _ = upConn.Close(); return }
	defer func(){ _ = clientConn.Close() }()

	clientConn.SetDeadline(time.Now().Add(p.idle))
	upConn.SetDeadline(time.Now().Add(p.idle))

	// Send 200 Connection Established
	_, _ = io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	// If there are buffered bytes (unlikely here), flush them upstream
	if buf.Reader.Buffered() > 0 {
		if _, err := io.Copy(upConn, buf.Reader); err != nil {
			_ = upConn.Close(); return
		}
	}

	// Bidirectional copy with deadline refresh
	var wg sync.WaitGroup
	pump := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		for {
			src.SetDeadline(time.Now().Add(p.idle))
			dst.SetDeadline(time.Now().Add(p.idle))
			n, er := src.Read(buf)
			if n > 0 {
				if _, ew := dst.Write(buf[:n]); ew != nil { return }
			}
			if er != nil {
				// Normal shutdown on EOF
				return
			}
		}
	}
	wg.Add(2)
	go pump(upConn, clientConn)
	go pump(clientConn, upConn)
	wg.Wait()
	_ = upConn.Close()
}

func parsePort(s string) (int, error) {
	var port int
	_, err := fmt.Sscanf(s, "%d", &port)
	if err != nil { return 0, err }
	if port <= 0 || port > 65535 { return 0, errors.New("bad port") }
	return port, nil
}

func toAddr(ip net.IP) netip.Addr {
	if ip4 := ip.To4(); ip4 != nil { a, _ := netip.AddrFromSlice(ip4); return a }
	a, _ := netip.AddrFromSlice(ip)
	return a
}

func main() {
	flag.Parse()

	ac, err := newACL(*allowCIDRs, *denyPrivate, *allowPorts)
	if err != nil { log.Fatalf("ACL error: %v", err) }

	px := newProxy(ac, *dialTimeout, *idleTimeout, *user, *pass)
	server := &http.Server{
		Addr:         *listenAddr,
		Handler:      px,
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
		IdleTimeout:  *idleTimeout,
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-done
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	log.Printf("proxy listening on %s (auth=%v denyPrivate=%v)", *listenAddr, *user != "" || *pass != "", *denyPrivate)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
	log.Println("shutdown complete")
}
