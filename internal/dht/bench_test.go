package dht

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
)

func BenchmarkValidateLookupValueSignedEnvelopeServiceRecord(b *testing.B) {
	id, err := identity.Generate()
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	rec, err := record.NewServiceRecord(id, "bench", "api", "[2001:db8::80]:4242", 10*time.Minute, now)
	if err != nil {
		b.Fatal(err)
	}
	payload := string(mustJSONBytes(b, rec))
	key := ServiceKey("bench.api")
	signed := mustSignedBenchmarkValue(b, id, key, payload, now)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := validateLookupValue(key, signed, now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStoreValidatedSignedEnvelopeServiceRecord(b *testing.B) {
	id, err := identity.Generate()
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	rec, err := record.NewServiceRecord(id, "bench", "api", "[2001:db8::81]:4242", 10*time.Minute, now)
	if err != nil {
		b.Fatal(err)
	}
	payload := string(mustJSONBytes(b, rec))
	key := ServiceKey("bench.api")
	server := newTestServer("bench-node")
	signed := mustSignedBenchmarkValue(b, id, key, payload, now)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, _, err := server.storeValidated(key, signed, now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRecursiveFindValueDetailedConfirmed3Sources(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := newTestServer("client-node")
	relayA := newTestServer("relay-a")
	relayB := newTestServer("relay-b")
	relayC := newTestServer("relay-c")

	addrA := startDHTBenchmarkListener(b, ctx, relayA)
	addrB := startDHTBenchmarkListener(b, ctx, relayB)
	addrC := startDHTBenchmarkListener(b, ctx, relayC)

	client.RT.AddNode(nodeInfo("relay-a", addrA))
	client.RT.AddNode(nodeInfo("relay-b", addrB))
	client.RT.AddNode(nodeInfo("relay-c", addrC))

	ownerID, err := identity.Generate()
	if err != nil {
		b.Fatal(err)
	}
	rec, err := record.NewServiceRecord(ownerID, "bench", "api", "[2001:db8::82]:4242", 10*time.Minute, time.Now())
	if err != nil {
		b.Fatal(err)
	}
	payload := string(mustJSONBytes(b, rec))
	key := ServiceKey("bench.api")
	signed := mustSignedBenchmarkValue(b, ownerID, key, payload, time.Now())
	relayA.StoreLocal(key, signed)
	relayB.StoreLocal(key, signed)
	relayC.StoreLocal(key, signed)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		result, err := client.RecursiveFindValueDetailed(ctx, key)
		if err != nil {
			b.Fatal(err)
		}
		if result.ExactMatchCount < 2 || result.TrustWeight < minTrustedConfirmationScore {
			b.Fatalf("expected confirmed result, got %+v", result)
		}
	}
}

func mustJSONBytes(b *testing.B, v any) []byte {
	b.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		b.Fatal(err)
	}
	return data
}

func nodeInfo(id, addr string) proto.NodeInfo {
	return proto.NodeInfo{ID: id, Addr: addr}
}

func mustBenchmarkServiceRecord(b *testing.B, nodeName, serviceName, address string, now time.Time) record.ServiceRecord {
	b.Helper()

	id, err := identity.Generate()
	if err != nil {
		b.Fatal(err)
	}
	rec, err := record.NewServiceRecord(id, nodeName, serviceName, address, 10*time.Minute, now)
	if err != nil {
		b.Fatal(err)
	}
	return rec
}

func mustSignedBenchmarkValue(b *testing.B, publisher identity.Identity, key, payload string, now time.Time) string {
	b.Helper()
	info, err := validateInnerLookupValue(key, payload, now)
	if err != nil {
		b.Fatal(err)
	}
	signed, err := wrapSignedEnvelope(publisher, key, payload, info, now)
	if err != nil {
		b.Fatal(err)
	}
	return signed
}

func startDHTBenchmarkListener(b *testing.B, ctx context.Context, srv *Server) string {
	b.Helper()

	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		b.Fatalf("listen dht benchmark: %v", err)
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()

				kind, err := proto.ReadHeader(conn)
				if err != nil || kind != proto.KindDHT {
					return
				}
				payload, err := proto.ReadLengthPrefixed(conn, 1024*1024)
				if err != nil {
					return
				}

				var req proto.DHTRequest
				if err := json.Unmarshal(payload, &req); err != nil {
					return
				}
				_ = srv.HandleDHT(ctx, conn, req)
			}(conn)
		}
	}()

	return ln.Addr().String()
}
