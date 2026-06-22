// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package serviceproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
	"github.com/vx6/vx6/internal/secure"
)

const maxRequestSize = 4 * 1024

type ConnectRequest struct {
	ServiceName string `json:"service_name"`
}

func HandleInbound(conn net.Conn, id identity.Identity, services map[string]string) error {
	fmt.Printf("[PROXY] Incoming request from %s\n", conn.RemoteAddr())

	secureConn, err := secure.Server(conn, proto.KindServiceConn, id)
	if err != nil {
		fmt.Printf("[PROXY] Secure handshake failed: %v\n", err)
		return err
	}

	reqPayload, err := proto.ReadLengthPrefixed(secureConn, maxRequestSize)
	if err != nil {
		fmt.Printf("[PROXY] Failed to read request: %v\n", err)
		return err
	}

	var req ConnectRequest
	if err := json.Unmarshal(reqPayload, &req); err != nil {
		return fmt.Errorf("decode service request: %w", err)
	}

	target, ok := services[req.ServiceName]
	if !ok {
		fmt.Printf("[PROXY] Reject: Service %q not found in local config\n", req.ServiceName)
		return fmt.Errorf("service %q not found", req.ServiceName)
	}

	// Ensure we dial explicitly on the local interface
	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		fmt.Printf("[PROXY] Reject: Could not connect to local target %s: %v\n", target, err)
		return err
	}
	defer targetConn.Close()

	fmt.Printf("[PROXY] Linked %s <-> %s (%s)\n", conn.RemoteAddr(), target, req.ServiceName)
	return proxyDuplex(secureConn, targetConn)
}

func ServeLocalForward(ctx context.Context, localListen string, service record.ServiceRecord, id identity.Identity, dialer func(context.Context) (net.Conn, error)) error {
	listener, err := net.Listen("tcp", localListen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", localListen, err)
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	fmt.Printf("local_forwarder\t%s\t%s\n", localListen, service.ServiceName)

	for {
		localConn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}

		go func() {
			defer localConn.Close()

			fmt.Printf("[TUNNEL] Dialing remote node for %s...\n", service.ServiceName)
			remoteConn, err := dialer(ctx)
			if err != nil {
				fmt.Printf("[TUNNEL] Connection failed: %v\n", err)
				return
			}
			defer remoteConn.Close()

			if err := proto.WriteHeader(remoteConn, proto.KindServiceConn); err != nil {
				return
			}
			secureConn, err := secure.Client(remoteConn, proto.KindServiceConn, id)
			if err != nil {
				fmt.Printf("[TUNNEL] Handshake failed: %v\n", err)
				return
			}

			payload, _ := json.Marshal(ConnectRequest{ServiceName: service.ServiceName})
			_ = proto.WriteLengthPrefixed(secureConn, payload)

			fmt.Printf("[TUNNEL] Active: Local:%s <-> Remote:%s\n", localListen, service.NodeName)
			_ = proxyDuplex(localConn, secureConn)
		}()
	}
}

func proxyDuplex(a, b io.ReadWriter) error {
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	copyPipe := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if closer, ok := dst.(io.Closer); ok {
			_ = closer.Close()
		}
		if closer, ok := src.(io.Closer); ok {
			_ = closer.Close()
		}
		errCh <- err
	}

	wg.Add(2)
	go copyPipe(a, b)
	go copyPipe(b, a)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil && !isProxyCloseError(err) {
			return err
		}
	}
	return nil
}

func isProxyCloseError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection") || strings.Contains(err.Error(), "closed pipe")
}
