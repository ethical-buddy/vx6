// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
	"github.com/vx6/vx6/internal/transfer"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

const maxMessageSize = 64 * 1024

const roundTripTimeout = 2 * time.Second

type Registry struct {
	mu            sync.RWMutex
	path          string
	byName        map[string]record.EndpointRecord
	byNode        map[string]record.EndpointRecord
	serviceByName map[string]record.ServiceRecord
}

func NewRegistry(path string) (*Registry, error) {
	r := &Registry{
		path:          path,
		byName:        map[string]record.EndpointRecord{},
		byNode:        map[string]record.EndpointRecord{},
		serviceByName: map[string]record.ServiceRecord{},
	}
	if path != "" {
		if err := r.load(); err != nil {
			return nil, err
		}
	}
	return r, nil
}

type request struct {
	Action        string                `json:"action"`
	Record        record.EndpointRecord `json:"record,omitempty"`
	ServiceRecord record.ServiceRecord  `json:"service_record,omitempty"`
	Name          string                `json:"name,omitempty"`
	NodeID        string                `json:"node_id,omitempty"`
	Service       string                `json:"service,omitempty"`
}

type response struct {
	OK             bool                    `json:"ok"`
	Error          string                  `json:"error,omitempty"`
	Record         record.EndpointRecord   `json:"record,omitempty"`
	ServiceRecord  record.ServiceRecord    `json:"service_record,omitempty"`
	Records        []record.EndpointRecord `json:"records,omitempty"`
	ServiceRecords []record.ServiceRecord  `json:"service_records,omitempty"`
}

func (r *Registry) HandleConn(conn net.Conn) error {
	defer conn.Close()

	payload, err := proto.ReadLengthPrefixed(conn, maxMessageSize)
	if err != nil {
		return err
	}

	var req request
	if err := json.Unmarshal(payload, &req); err != nil {
		return writeResponse(conn, response{Error: fmt.Sprintf("decode request: %v", err)})
	}

	switch req.Action {
	case "publish":
		return r.handlePublish(conn, req.Record)
	case "publish_service":
		return r.handlePublishService(conn, req.ServiceRecord)
	case "resolve":
		return r.handleResolve(conn, req.Name, req.NodeID)
	case "resolve_service":
		return r.handleResolveService(conn, req.Service)
	case "snapshot":
		return r.handleSnapshot(conn)
	default:
		return writeResponse(conn, response{Error: fmt.Sprintf("unknown action %q", req.Action)})
	}
}

func (r *Registry) handlePublish(conn net.Conn, rec record.EndpointRecord) error {
	if err := record.VerifyEndpointRecord(rec, time.Now()); err != nil {
		return writeResponse(conn, response{Error: err.Error()})
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.byName[rec.NodeName]; ok && existing.NodeID != rec.NodeID {
		return writeResponse(conn, response{Error: fmt.Sprintf("node name %q already belongs to %s", rec.NodeName, existing.NodeID)})
	}

	if existing, ok := r.byNode[rec.NodeID]; ok {
		existingIssuedAt, _ := time.Parse(time.RFC3339, existing.IssuedAt)
		newIssuedAt, _ := time.Parse(time.RFC3339, rec.IssuedAt)
		if existingIssuedAt.After(newIssuedAt) {
			return writeResponse(conn, response{Error: "new record is older than stored record"})
		}
	}

	r.upsertEndpointLocked(rec)
	if err := r.saveLocked(); err != nil {
		return writeResponse(conn, response{Error: err.Error()})
	}

	return writeResponse(conn, response{OK: true, Record: rec})
}

func (r *Registry) handleResolve(conn net.Conn, name, nodeID string) error {
	rec, err := r.resolve(name, nodeID)
	if err != nil {
		return writeResponse(conn, response{Error: err.Error()})
	}
	return writeResponse(conn, response{OK: true, Record: rec})
}

func (r *Registry) handlePublishService(conn net.Conn, rec record.ServiceRecord) error {
	if err := record.VerifyServiceRecord(rec, time.Now()); err != nil {
		return writeResponse(conn, response{Error: err.Error()})
	}
	if rec.IsPrivate {
		return writeResponse(conn, response{Error: "private services are not published through the shared registry"})
	}
	if rec.IsHidden {
		return writeResponse(conn, response{Error: "hidden services are not published through the shared registry"})
	}

	fullName := record.ServiceLookupKey(rec)

	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.serviceByName[fullName]; ok {
		oldIssuedAt, _ := time.Parse(time.RFC3339, existing.IssuedAt)
		newIssuedAt, _ := time.Parse(time.RFC3339, rec.IssuedAt)
		if oldIssuedAt.After(newIssuedAt) {
			return writeResponse(conn, response{Error: "new service record is older than stored record"})
		}
	}

	r.serviceByName[fullName] = rec
	if err := r.saveLocked(); err != nil {
		return writeResponse(conn, response{Error: err.Error()})
	}

	return writeResponse(conn, response{OK: true, ServiceRecord: rec})
}

func (r *Registry) handleResolveService(conn net.Conn, service string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rec, ok := r.serviceByName[service]
	if !ok {
		return writeResponse(conn, response{Error: "service record not found"})
	}
	if err := record.VerifyServiceRecord(rec, time.Now()); err != nil {
		return writeResponse(conn, response{Error: fmt.Sprintf("stored service record invalid: %v", err)})
	}

	return writeResponse(conn, response{OK: true, ServiceRecord: rec})
}

func (r *Registry) handleSnapshot(conn net.Conn) error {
	records, services := r.Snapshot()
	return writeResponse(conn, response{OK: true, Records: records, ServiceRecords: services})
}

func (r *Registry) resolve(name, nodeID string) (record.EndpointRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var rec record.EndpointRecord
	var ok bool

	switch {
	case name != "":
		rec, ok = r.byName[name]
	case nodeID != "":
		rec, ok = r.byNode[nodeID]
	default:
		return record.EndpointRecord{}, fmt.Errorf("resolve requires name or node_id")
	}
	if !ok {
		return record.EndpointRecord{}, fmt.Errorf("record not found")
	}
	if err := record.VerifyEndpointRecord(rec, time.Now()); err != nil {
		return record.EndpointRecord{}, fmt.Errorf("stored record invalid: %v", err)
	}
	return rec, nil
}

func (r *Registry) Snapshot() ([]record.EndpointRecord, []record.ServiceRecord) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.byName))
	for name := range r.byName {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]record.EndpointRecord, 0, len(names))
	for _, name := range names {
		out = append(out, r.byName[name])
	}
	serviceNames := make([]string, 0, len(r.serviceByName))
	for name := range r.serviceByName {
		serviceNames = append(serviceNames, name)
	}
	sort.Strings(serviceNames)
	serviceOut := make([]record.ServiceRecord, 0, len(serviceNames))
	for _, name := range serviceNames {
		serviceOut = append(serviceOut, r.serviceByName[name])
	}

	return out, serviceOut
}

func (r *Registry) ResolveLocal(name, nodeID string) (record.EndpointRecord, error) {
	return r.resolve(name, nodeID)
}

func (r *Registry) ResolveServiceLocal(fullName string) (record.ServiceRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rec, ok := r.serviceByName[fullName]
	if !ok {
		return record.ServiceRecord{}, fmt.Errorf("service record not found")
	}
	if err := record.VerifyServiceRecord(rec, time.Now()); err != nil {
		return record.ServiceRecord{}, err
	}
	return rec, nil
}

func (r *Registry) Import(records []record.EndpointRecord, serviceRecords []record.ServiceRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	changed := false
	for _, rec := range records {
		if err := record.VerifyEndpointRecord(rec, time.Now()); err != nil {
			continue
		}
		existing, ok := r.byNode[rec.NodeID]
		if ok {
			oldIssuedAt, _ := time.Parse(time.RFC3339, existing.IssuedAt)
			newIssuedAt, _ := time.Parse(time.RFC3339, rec.IssuedAt)
			if !newIssuedAt.After(oldIssuedAt) {
				continue
			}
		}
		r.upsertEndpointLocked(rec)
		changed = true
	}

	for _, rec := range serviceRecords {
		if err := record.VerifyServiceRecord(rec, time.Now()); err != nil {
			continue
		}
		if rec.IsPrivate || rec.IsHidden {
			continue
		}
		fullName := record.ServiceLookupKey(rec)
		existing, ok := r.serviceByName[fullName]
		if ok {
			oldIssuedAt, _ := time.Parse(time.RFC3339, existing.IssuedAt)
			newIssuedAt, _ := time.Parse(time.RFC3339, rec.IssuedAt)
			if !newIssuedAt.After(oldIssuedAt) {
				continue
			}
		}
		r.serviceByName[fullName] = rec
		changed = true
	}

	if changed {
		return r.saveLocked()
	}
	return nil
}

func (r *Registry) load() error {
	data, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read registry: %w", err)
	}

	var snapshot response
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return fmt.Errorf("decode registry: %w", err)
	}
	for _, rec := range snapshot.Records {
		if err := record.VerifyEndpointRecord(rec, time.Now()); err != nil {
			continue
		}
		r.upsertEndpointLocked(rec)
	}
	for _, rec := range snapshot.ServiceRecords {
		if err := record.VerifyServiceRecord(rec, time.Now()); err != nil {
			continue
		}
		if rec.IsPrivate || rec.IsHidden {
			continue
		}
		r.serviceByName[record.ServiceLookupKey(rec)] = rec
	}
	return nil
}

func (r *Registry) saveLocked() error {
	if r.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		return fmt.Errorf("create registry directory: %w", err)
	}

	names := make([]string, 0, len(r.byName))
	for name := range r.byName {
		names = append(names, name)
	}
	sort.Strings(names)

	records := make([]record.EndpointRecord, 0, len(names))
	for _, name := range names {
		records = append(records, r.byName[name])
	}

	serviceNames := make([]string, 0, len(r.serviceByName))
	for name := range r.serviceByName {
		serviceNames = append(serviceNames, name)
	}
	sort.Strings(serviceNames)
	serviceRecords := make([]record.ServiceRecord, 0, len(serviceNames))
	for _, name := range serviceNames {
		serviceRecords = append(serviceRecords, r.serviceByName[name])
	}

	data, err := json.MarshalIndent(response{Records: records, ServiceRecords: serviceRecords}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode registry: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(r.path, data, 0o644); err != nil {
		return fmt.Errorf("write registry: %w", err)
	}
	return nil
}

func (r *Registry) upsertEndpointLocked(rec record.EndpointRecord) {
	if existing, ok := r.byNode[rec.NodeID]; ok && existing.NodeName != "" && existing.NodeName != rec.NodeName {
		delete(r.byName, existing.NodeName)
	}
	r.byName[rec.NodeName] = rec
	r.byNode[rec.NodeID] = rec
}

func Publish(ctx context.Context, address string, rec record.EndpointRecord) (record.EndpointRecord, error) {
	resp, err := roundTrip(ctx, address, request{
		Action: "publish",
		Record: rec,
	})
	if err != nil {
		return record.EndpointRecord{}, err
	}
	if !resp.OK {
		return record.EndpointRecord{}, fmt.Errorf(resp.Error)
	}
	return resp.Record, nil
}

func PublishService(ctx context.Context, address string, rec record.ServiceRecord) (record.ServiceRecord, error) {
	resp, err := roundTrip(ctx, address, request{
		Action:        "publish_service",
		ServiceRecord: rec,
	})
	if err != nil {
		return record.ServiceRecord{}, err
	}
	if !resp.OK {
		return record.ServiceRecord{}, fmt.Errorf(resp.Error)
	}
	return resp.ServiceRecord, nil
}

func Resolve(ctx context.Context, address, name, nodeID string) (record.EndpointRecord, error) {
	resp, err := roundTrip(ctx, address, request{
		Action: "resolve",
		Name:   name,
		NodeID: nodeID,
	})
	if err != nil {
		return record.EndpointRecord{}, err
	}
	if !resp.OK {
		return record.EndpointRecord{}, fmt.Errorf(resp.Error)
	}
	if err := record.VerifyEndpointRecord(resp.Record, time.Now()); err != nil {
		return record.EndpointRecord{}, err
	}
	return resp.Record, nil
}

func ResolveService(ctx context.Context, address, service string) (record.ServiceRecord, error) {
	resp, err := roundTrip(ctx, address, request{
		Action:  "resolve_service",
		Service: service,
	})
	if err != nil {
		return record.ServiceRecord{}, err
	}
	if !resp.OK {
		return record.ServiceRecord{}, fmt.Errorf(resp.Error)
	}
	if err := record.VerifyServiceRecord(resp.ServiceRecord, time.Now()); err != nil {
		return record.ServiceRecord{}, err
	}
	return resp.ServiceRecord, nil
}

func Snapshot(ctx context.Context, address string) ([]record.EndpointRecord, []record.ServiceRecord, error) {
	resp, err := roundTrip(ctx, address, request{Action: "snapshot"})
	if err != nil {
		return nil, nil, err
	}
	if !resp.OK {
		return nil, nil, fmt.Errorf(resp.Error)
	}
	return resp.Records, resp.ServiceRecords, nil
}

func roundTrip(ctx context.Context, address string, req request) (response, error) {
	if err := transfer.ValidateIPv6Address(address); err != nil {
		return response{}, err
	}

	dialCtx, cancel := context.WithTimeout(ctx, roundTripTimeout)
	defer cancel()

	conn, err := vxtransport.DialContext(dialCtx, vxtransport.ModeAuto, address)
	if err != nil {
		return response{}, fmt.Errorf("dial discovery endpoint %s: %w", address, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(roundTripTimeout))

	if err := proto.WriteHeader(conn, proto.KindDiscoveryReq); err != nil {
		return response{}, err
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return response{}, fmt.Errorf("encode request: %w", err)
	}
	if err := proto.WriteLengthPrefixed(conn, payload); err != nil {
		return response{}, err
	}

	kind, err := proto.ReadHeader(conn)
	if err != nil {
		return response{}, err
	}
	if kind != proto.KindDiscoveryRes {
		return response{}, fmt.Errorf("unexpected response kind %d", kind)
	}

	reply, err := proto.ReadLengthPrefixed(conn, maxMessageSize)
	if err != nil {
		return response{}, err
	}

	var resp response
	if err := json.Unmarshal(reply, &resp); err != nil {
		return response{}, fmt.Errorf("decode response: %w", err)
	}

	return resp, nil
}

func writeResponse(conn net.Conn, resp response) error {
	if resp.Error == "" {
		resp.OK = true
	}
	if err := proto.WriteHeader(conn, proto.KindDiscoveryRes); err != nil {
		return err
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("encode response: %w", err)
	}
	return proto.WriteLengthPrefixed(conn, payload)
}
