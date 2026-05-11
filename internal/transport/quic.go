package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// quicListen starts a QUIC listener on addr and wraps it as a net.Listener.
// Each accepted QUIC connection exposes its first bidirectional stream as a
// net.Conn so the rest of VX6 (which speaks net.Conn) needs no changes.
func quicListen(addr string) (net.Listener, error) {
	tlsCfg, err := selfSignedTLS()
	if err != nil {
		return nil, err
	}
	ln, err := quic.ListenAddr(addr, tlsCfg, quicCfg())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &quicListener{ln: ln, ctx: ctx, cancel: cancel}, nil
}

// quicDial opens a QUIC connection to addr and returns its first stream as a net.Conn.
func quicDial(ctx context.Context, addr string) (net.Conn, error) {
	tlsCfg := &tls.Config{
		// Peer identity is verified by VX6's secure/session layer above transport.
		// InsecureSkipVerify skips TLS certificate chain validation only — the
		// Ed25519-based node identity check still happens in internal/secure.
		InsecureSkipVerify: true,
		NextProtos:         []string{"vx6/1"},
		MinVersion:         tls.VersionTLS13,
	}
	conn, err := quic.DialAddr(ctx, addr, tlsCfg, quicCfg())
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "stream open failed")
		return nil, err
	}
	return &quicStreamConn{conn: conn, stream: stream}, nil
}

// quicCfg returns shared QUIC connection settings.
func quicCfg() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	}
}

// selfSignedTLS generates a throw-away TLS certificate for the QUIC listener.
// Real peer authentication is handled by VX6's secure/session handshake on top.
func selfSignedTLS() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vx6-quic"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(87600 * time.Hour), // 10 years
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		}},
		NextProtos: []string{"vx6/1"},
		MinVersion: tls.VersionTLS13,
	}, nil
}

// ── quicListener wraps *quic.Listener as net.Listener ─────────────────────────

type quicListener struct {
	ln     *quic.Listener
	ctx    context.Context    // cancelled when Close() is called
	cancel context.CancelFunc // lets Accept() unblock cleanly on shutdown
}

func (l *quicListener) Accept() (net.Conn, error) {
	// Use our own cancellable context so Accept unblocks immediately
	// when Close() is called, rather than blocking forever.
	conn, err := l.ln.Accept(l.ctx)
	if err != nil {
		return nil, err
	}
	// Use the connection's own context so AcceptStream unblocks if the
	// connection drops before the first stream is opened.
	stream, err := conn.AcceptStream(conn.Context())
	if err != nil {
		_ = conn.CloseWithError(0, "stream accept failed")
		return nil, err
	}
	return &quicStreamConn{conn: conn, stream: stream}, nil
}

func (l *quicListener) Close() error {
	l.cancel() // unblock any Accept() call waiting on l.ctx
	return l.ln.Close()
}

func (l *quicListener) Addr() net.Addr { return l.ln.Addr() }

// ── quicStreamConn wraps a QUIC stream as net.Conn ────────────────────────────

type quicStreamConn struct {
	conn   *quic.Conn
	stream *quic.Stream
}

func (c *quicStreamConn) Read(b []byte) (int, error)  { return c.stream.Read(b) }
func (c *quicStreamConn) Write(b []byte) (int, error) { return c.stream.Write(b) }

func (c *quicStreamConn) Close() error {
	// Step 1: Close the write side of the stream gracefully.
	// This sends a FIN to the peer so they know no more data is coming,
	// and lets them drain any remaining bytes before we disappear.
	// This is stream-level, not connection-level.
	if err := c.stream.Close(); err != nil {
		// Stream already closed or reset — cancel read side and return.
		c.stream.CancelRead(0)
		return err
	}
	// Step 2: Cancel the read side — we are done receiving on this stream.
	c.stream.CancelRead(0)

	// Step 3: Do NOT call conn.CloseWithError here.
	// In this single-stream-per-connection model the QUIC connection
	// idles out naturally via MaxIdleTimeout (30s). Killing the connection
	// immediately here would race with the peer still reading the FIN.
	return nil
}

func (c *quicStreamConn) LocalAddr() net.Addr             { return c.conn.LocalAddr() }
func (c *quicStreamConn) RemoteAddr() net.Addr            { return c.conn.RemoteAddr() }
func (c *quicStreamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *quicStreamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *quicStreamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }