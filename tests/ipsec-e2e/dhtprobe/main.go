package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vx6/vx6/internal/config"
	"github.com/vx6/vx6/internal/dht"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/ipsec"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
	strictjson "github.com/vx6/vx6/internal/strictjson"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("dhtprobe", flag.ContinueOnError)
	peerPath := fs.String("peer-record", "", "signed endpoint record for the remote node")
	outDir := fs.String("out", "", "scenario artifact directory")
	typ := fs.String("type", "", "DHT request type")
	action := fs.String("action", "", "DHT action")
	target := fs.String("target", "", "wire target")
	dataKind := fs.String("data-kind", "", "optional signed payload: endpoint or service")
	recordName := fs.String("record-name", "", "owner node name for generated signed data")
	recordAddr := fs.String("record-address", "", "IPv6 endpoint for generated signed data")
	serviceName := fs.String("service-name", "", "service name for generated signed data")
	sequence := fs.Uint64("sequence", 1, "endpoint record sequence")
	tamperSignature := fs.Bool("tamper-signature", false, "corrupt the generated endpoint signature")
	rawRequest := fs.String("raw-request", "", "send this exact JSON body instead of a structured request")
	corrupt := fs.String("corrupt", "", "corruption mode: unknown-field, duplicate-field, oversized")
	expectDrop := fs.Bool("expect-drop", false, "require the remote node to close without a DHT response")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *peerPath == "" || *outDir == "" || *typ == "" || *action == "" || *target == "" {
		return errors.New("peer-record, out, type, action, and target are required")
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	result := map[string]any{
		"transport":      "TCP guarded by IKEv2/ESP",
		"request_type":   *typ,
		"request_action": *action,
		"request_target": *target,
		"passed":         false,
	}
	defer func() {
		data, _ := json.MarshalIndent(result, "", "  ")
		_ = os.WriteFile(filepath.Join(*outDir, "result.json"), append(data, '\n'), 0o644)
	}()

	requestBody, err := makeRequestBody(*typ, *action, *target, *dataKind, *recordName, *recordAddr, *serviceName, *sequence, *tamperSignature, *rawRequest, *corrupt)
	if err != nil {
		return err
	}
	requestPath := filepath.Join(*outDir, "request.json")
	if *corrupt == "oversized" {
		requestPath = filepath.Join(*outDir, "request.bin")
	}
	if err := os.WriteFile(requestPath, requestBody, 0o644); err != nil {
		return err
	}

	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}
	idStore, err := identity.NewStoreForConfig(store.Path())
	if err != nil {
		return err
	}
	localID, err := idStore.Load()
	if err != nil {
		return err
	}
	peerBytes, err := os.ReadFile(*peerPath)
	if err != nil {
		return err
	}
	var peer record.EndpointRecord
	if err := strictjson.Decode(peerBytes, &peer); err != nil {
		return fmt.Errorf("decode peer record: %w", err)
	}
	result["remote_node_id"] = peer.NodeID
	if err := record.VerifyEndpointRecord(peer, time.Now()); err != nil {
		return fmt.Errorf("verify peer record: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	tunnel, err := ipsec.NewClient(ipsec.DefaultSocket(), cfg.Node.AdvertiseAddr, localID)
	if err != nil {
		return err
	}
	guarded := vxtransport.WithExpectedPeerID(ctx, peer.NodeID)
	guarded = vxtransport.WithDialGuard(guarded, func(ctx context.Context, addr string) error {
		if addr != peer.Address {
			return fmt.Errorf("probe endpoint mismatch: got %s want %s", addr, peer.Address)
		}
		return tunnel.EnsurePeer(ctx, peer)
	})
	conn, err := vxtransport.DialContext(guarded, vxtransport.ModeTCP, peer.Address)
	if err != nil {
		return fmt.Errorf("protected DHT dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := proto.WriteHeader(conn, proto.KindDHT); err != nil {
		return err
	}
	if err := proto.WriteLengthPrefixed(conn, requestBody); err != nil {
		if *expectDrop && (strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "broken pipe")) {
			result["expected_drop"] = true
			result["passed"] = true
			result["drop_error"] = err.Error()
			return saveDrop(*outDir, err)
		}
		return err
	}
	result["request_bytes"] = len(requestBody)

	responsePath := filepath.Join(*outDir, "response.json")
	if *corrupt == "oversized" {
		responsePath = filepath.Join(*outDir, "response.bin")
	}
	kind, err := proto.ReadHeader(conn)
	if err != nil {
		if *expectDrop && (errors.Is(err, io.EOF) || strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "closed")) {
			result["expected_drop"] = true
			result["passed"] = true
			result["drop_error"] = err.Error()
			return saveDrop(*outDir, err)
		}
		return fmt.Errorf("read response header: %w", err)
	}
	if kind != proto.KindDHT {
		return fmt.Errorf("unexpected response kind 0x%x", kind)
	}
	responseBody, err := proto.ReadLengthPrefixed(conn, 2*1024*1024)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	if err := os.WriteFile(responsePath, responseBody, 0o644); err != nil {
		return err
	}
	if *expectDrop {
		return errors.New("expected the peer to drop the malformed request, but it returned a DHT response")
	}
	var response proto.DHTResponse
	if err := strictjson.Decode(responseBody, &response); err != nil {
		return fmt.Errorf("decode strict DHT response: %w", err)
	}
	if response.Version != proto.DHTWireVersion || response.Type != proto.DHTRequestType(*typ) {
		return fmt.Errorf("response version/type mismatch: version=%d type=%q", response.Version, response.Type)
	}
	if len(response.Nodes) > 4 {
		return fmt.Errorf("responder exceeded four-referral ceiling: got %d", len(response.Nodes))
	}
	for _, node := range response.Nodes {
		if err := dht.VerifyNodeInfo(node, time.Now()); err != nil {
			return fmt.Errorf("invalid signed referral %s: %w", node.ID, err)
		}
	}
	result["passed"] = true
	result["response_type"] = response.Type
	result["referrals"] = len(response.Nodes)
	result["value_bytes"] = len(response.Value)
	result["verified_referrals"] = len(response.Nodes)
	return nil
}

func makeRequestBody(typ, action, target, dataKind, nodeName, address, serviceName string, sequence uint64, tamper bool, raw, corrupt string) ([]byte, error) {
	if raw != "" {
		return []byte(raw), nil
	}
	if corrupt == "unknown-field" {
		return []byte(fmt.Sprintf(`{"version":1,"type":%q,"action":%q,"target":%q,"data":"","unexpected":true}`, typ, action, target)), nil
	}
	if corrupt == "uppercase-hash" {
		return []byte(fmt.Sprintf(`{"version":1,"type":%q,"action":%q,"target":%q,"data":""}`, typ, action, target)), nil
	}
	if corrupt == "duplicate-field" {
		return []byte(fmt.Sprintf(`{"version":1,"type":%q,"action":%q,"action":%q,"target":%q,"data":""}`, typ, action, action, target)), nil
	}
	if corrupt == "oversized" {
		return bytes.Repeat([]byte{'x'}, 1024*1024+32), nil
	}
	request := proto.DHTRequest{Version: proto.DHTWireVersion, Type: proto.DHTRequestType(typ), Action: action, Target: target}
	if dataKind != "" {
		localStore, err := config.NewStore("")
		if err != nil {
			return nil, err
		}
		identityStore, err := identity.NewStoreForConfig(localStore.Path())
		if err != nil {
			return nil, err
		}
		id, err := identityStore.Load()
		if err != nil {
			return nil, err
		}
		now := time.Now()
		switch dataKind {
		case "endpoint":
			if nodeName == "" || address == "" {
				return nil, errors.New("endpoint data requires record-name and record-address")
			}
			rec, err := record.NewEndpointRecordV2(id, nodeName, address, sequence, time.Hour, now)
			if err != nil {
				return nil, err
			}
			data, err := json.Marshal(rec)
			if err != nil {
				return nil, err
			}
			request.Data = string(data)
			if request.Type == proto.DHTTypeUpdateIP {
				request.Data, err = dht.WrapSignedValue(id, target, string(data), now)
				if err != nil {
					return nil, err
				}
				if tamper {
					var envelope dht.SignedEnvelope
					if err := json.Unmarshal([]byte(request.Data), &envelope); err != nil {
						return nil, err
					}
					var inner record.EndpointRecord
					if err := json.Unmarshal([]byte(envelope.Value), &inner); err != nil {
						return nil, err
					}
					inner.Signature = strings.Repeat("A", 88)
					innerData, err := json.Marshal(inner)
					if err != nil {
						return nil, err
					}
					envelope.Value = string(innerData)
					wrapped, err := json.Marshal(envelope)
					if err != nil {
						return nil, err
					}
					request.Data = string(wrapped)
				}
			}
		case "service":
			if nodeName == "" || address == "" || serviceName == "" {
				return nil, errors.New("service data requires record-name, record-address and service-name")
			}
			rec, err := record.NewServiceRecord(id, nodeName, serviceName, address, time.Hour, now)
			if err != nil {
				return nil, err
			}
			data, err := json.Marshal(rec)
			if err != nil {
				return nil, err
			}
			request.Data, err = dht.WrapSignedValue(id, target, string(data), now)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unknown data kind %q", dataKind)
		}
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(request)
}

func saveDrop(outDir string, err error) error {
	response, _ := json.MarshalIndent(map[string]any{"response": "connection_dropped", "error": err.Error()}, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "response.json"), response, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, "result.json"), []byte(`{"expected_drop":true,"passed":true}`), 0o644)
}
