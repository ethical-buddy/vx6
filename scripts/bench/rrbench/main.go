// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

// rrbench is a small request/response load generator used by the IPsec
// baseline benchmark (issue #51). It deliberately has no VX6 dependencies so
// the same binary measures plain sockets and sockets carried through an ESP
// SA. It is a benchmark helper, not part of the VX6 runtime.
//
//	rrbench -mode server -listen [fd00:56::b]:4242
//	rrbench -mode client -addr [fd00:56::b]:4242 -n 5000 -c 1 -size 64
//	rrbench -mode client -addr ... -c 64 -newconn   # connection churn
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type result struct {
	Requests    int     `json:"requests"`
	Errors      int64   `json:"errors"`
	Concurrency int     `json:"concurrency"`
	Size        int     `json:"size"`
	NewConn     bool    `json:"new_conn_per_request"`
	ElapsedSec  float64 `json:"elapsed_sec"`
	RPS         float64 `json:"requests_per_sec"`
	P50us       float64 `json:"p50_us"`
	P95us       float64 `json:"p95_us"`
	P99us       float64 `json:"p99_us"`
	MaxUs       float64 `json:"max_us"`
	MeanUs      float64 `json:"mean_us"`
}

func main() {
	mode := flag.String("mode", "client", "server or client")
	listen := flag.String("listen", "[::1]:4242", "server listen address")
	addr := flag.String("addr", "[::1]:4242", "client target address")
	local := flag.String("local", "", "optional client source address (host:port)")
	n := flag.Int("n", 2000, "total requests")
	c := flag.Int("c", 1, "concurrent connections")
	size := flag.Int("size", 64, "request and response payload bytes")
	newConn := flag.Bool("newconn", false, "open a new TCP connection per request")
	timeout := flag.Duration("timeout", 5*time.Second, "per-request timeout")
	flag.Parse()

	switch *mode {
	case "server":
		if err := serve(*listen); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "client":
		res := run(*addr, *local, *n, *c, *size, *newConn, *timeout)
		_ = json.NewEncoder(os.Stdout).Encode(res)
		if res.Errors > 0 {
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown -mode")
		os.Exit(2)
	}
}

// Wire format: 4-byte big-endian length, then payload. The server echoes it.
func serve(listen string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(conn net.Conn) {
			defer conn.Close()
			var hdr [4]byte
			buf := make([]byte, 0, 1<<16)
			for {
				if _, err := io.ReadFull(conn, hdr[:]); err != nil {
					return
				}
				l := int(binary.BigEndian.Uint32(hdr[:]))
				if l > 16<<20 {
					return
				}
				if cap(buf) < l {
					buf = make([]byte, l)
				}
				buf = buf[:l]
				if _, err := io.ReadFull(conn, buf); err != nil {
					return
				}
				if _, err := conn.Write(append(hdr[:], buf...)); err != nil {
					return
				}
			}
		}(conn)
	}
}

func dial(addr, local string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	if local != "" {
		la, err := net.ResolveTCPAddr("tcp", local)
		if err != nil {
			return nil, err
		}
		d.LocalAddr = la
	}
	return d.Dial("tcp", addr)
}

func roundTrip(conn net.Conn, req, resp []byte, timeout time.Duration) error {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	_, err := io.ReadFull(conn, resp)
	return err
}

func run(addr, local string, n, c, size int, newConn bool, timeout time.Duration) result {
	if c < 1 {
		c = 1
	}
	req := make([]byte, 4+size)
	binary.BigEndian.PutUint32(req, uint32(size))
	for i := range req[4:] {
		req[4+i] = byte(i)
	}
	lat := make([]time.Duration, n)
	var next int64 = -1
	var errs int64
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < c; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := make([]byte, 4+size)
			var conn net.Conn
			defer func() {
				if conn != nil {
					conn.Close()
				}
			}()
			for {
				i := int(atomic.AddInt64(&next, 1))
				if i >= n {
					return
				}
				t0 := time.Now()
				if conn == nil {
					var err error
					conn, err = dial(addr, local, timeout)
					if err != nil {
						atomic.AddInt64(&errs, 1)
						lat[i] = -1
						continue
					}
				}
				if err := roundTrip(conn, req, resp, timeout); err != nil {
					atomic.AddInt64(&errs, 1)
					lat[i] = -1
					conn.Close()
					conn = nil
					continue
				}
				lat[i] = time.Since(t0)
				if newConn {
					conn.Close()
					conn = nil
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	ok := lat[:0]
	for _, d := range lat {
		if d >= 0 {
			ok = append(ok, d)
		}
	}
	sort.Slice(ok, func(i, j int) bool { return ok[i] < ok[j] })
	res := result{Requests: n, Errors: errs, Concurrency: c, Size: size, NewConn: newConn, ElapsedSec: elapsed.Seconds()}
	if len(ok) > 0 {
		var sum time.Duration
		for _, d := range ok {
			sum += d
		}
		pct := func(p float64) float64 { return float64(ok[int(p*float64(len(ok)-1))].Nanoseconds()) / 1e3 }
		res.P50us, res.P95us, res.P99us = pct(0.50), pct(0.95), pct(0.99)
		res.MaxUs = float64(ok[len(ok)-1].Nanoseconds()) / 1e3
		res.MeanUs = float64(sum.Nanoseconds()) / float64(len(ok)) / 1e3
		res.RPS = float64(len(ok)) / elapsed.Seconds()
	}
	return res
}
