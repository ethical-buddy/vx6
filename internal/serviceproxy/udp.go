package serviceproxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vx6/vx6/internal/record"
)

const (
	udpMagic          = "VX6U"
	udpVersion        = 1
	udpFixedHeader    = 14
	maxUDPDatagramLen = 65507
	maxServiceNameLen = 64
	maxUDPSessions    = 4096
	maxUDPAuthEntries = 4096
	udpSessionIdle    = time.Minute
	peerAuthCacheTTL  = 2 * time.Second
)

type UDPAuthenticator func(context.Context, string) (record.EndpointRecord, bool)

type udpAssociation struct {
	key      string
	service  string
	peerID   string
	peerAddr *net.UDPAddr
	flowID   uint64
	backend  *net.UDPConn
	lastSeen atomic.Int64
	close    sync.Once
}

func (a *udpAssociation) Close() {
	a.close.Do(func() { _ = a.backend.Close() })
}

// UDPServicePort reserves the endpoint port plus two for VX6 UDP services;
// endpoint port plus one is already used by the liveness probe.
func UDPServicePort(endpoint string) (string, error) {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid VX6 endpoint: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port >= 65534 {
		return "", fmt.Errorf("endpoint port %q cannot reserve its UDP service port", portText)
	}
	return net.JoinHostPort(host, strconv.Itoa(port+2)), nil
}

func EncodeUDPServiceDatagram(service string, flowID uint64, payload []byte) ([]byte, error) {
	if flowID == 0 {
		return nil, errors.New("invalid VX6 UDP flow id")
	}
	if err := record.ValidateServiceName(service); err != nil {
		return nil, err
	}
	if len(service) > maxServiceNameLen {
		return nil, errors.New("service name too long for UDP envelope")
	}
	if udpFixedHeader+len(service)+len(payload) > maxUDPDatagramLen {
		return nil, errors.New("UDP service datagram exceeds the supported payload size")
	}
	packet := make([]byte, udpFixedHeader+len(service)+len(payload))
	copy(packet[:4], udpMagic)
	packet[4] = udpVersion
	packet[5] = byte(len(service))
	binary.BigEndian.PutUint64(packet[6:14], flowID)
	copy(packet[14:], service)
	copy(packet[14+len(service):], payload)
	return packet, nil
}

func DecodeUDPServiceDatagram(packet []byte) (string, uint64, []byte, error) {
	if len(packet) < udpFixedHeader || len(packet) > maxUDPDatagramLen || string(packet[:4]) != udpMagic || packet[4] != udpVersion {
		return "", 0, nil, errors.New("invalid VX6 UDP envelope")
	}
	nameLen := int(packet[5])
	if nameLen == 0 || nameLen > maxServiceNameLen || len(packet) < udpFixedHeader+nameLen {
		return "", 0, nil, errors.New("invalid VX6 UDP service name length")
	}
	name := string(packet[udpFixedHeader : udpFixedHeader+nameLen])
	if err := record.ValidateServiceName(name); err != nil {
		return "", 0, nil, err
	}
	flowID := binary.BigEndian.Uint64(packet[6:14])
	if flowID == 0 {
		return "", 0, nil, errors.New("invalid VX6 UDP flow id")
	}
	return name, flowID, packet[udpFixedHeader+nameLen:], nil
}

func ServeUDPServices(ctx context.Context, socket *net.UDPConn, policies func() map[string]ServicePolicy, authenticate UDPAuthenticator) error {
	if socket == nil || policies == nil || authenticate == nil {
		return errors.New("UDP service listener requires socket, policy source, and peer authenticator")
	}
	associations := make(map[string]*udpAssociation)
	var mu sync.Mutex
	peerCache := make(map[string]peerAuthEntry)
	buffer := make([]byte, 65535)
	cleanup := time.NewTicker(10 * time.Second)
	defer cleanup.Stop()
	defer func() {
		mu.Lock()
		for key, association := range associations {
			association.Close()
			delete(associations, key)
		}
		mu.Unlock()
	}()
	go func() {
		<-ctx.Done()
		_ = socket.Close()
		mu.Lock()
		for key, association := range associations {
			association.Close()
			delete(associations, key)
		}
		mu.Unlock()
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-cleanup.C:
			}
			now := time.Now()
			mu.Lock()
			for key, association := range associations {
				if now.Sub(time.Unix(0, association.lastSeen.Load())) > udpSessionIdle {
					association.Close()
					delete(associations, key)
				}
			}
			for ip, entry := range peerCache {
				if now.After(entry.expires) {
					delete(peerCache, ip)
				}
			}
			mu.Unlock()
		}
	}()
	for {
		n, remote, err := socket.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		service, flowID, payload, err := DecodeUDPServiceDatagram(buffer[:n])
		if err != nil || flowID == 0 {
			continue
		}
		policy, ok := policies()[service]
		if !ok || policy.Target == "" || record.NormalizeServiceProtocol(policy.Protocol) != record.ServiceProtocolUDP {
			continue
		}
		peer, authenticated := cachedUDPIdentity(ctx, remote, peerCache, &mu, authenticate)
		if !authenticated {
			continue
		}
		if policy.Private {
			verified, verifyErr := record.VerifyEndpoint(peer, time.Now())
			if verifyErr != nil || !policy.Allows(verified.Endpoint().NodeID) {
				continue
			}
		}
		key := remote.String() + "/" + service + "/" + strconv.FormatUint(flowID, 10)
		mu.Lock()
		association := associations[key]
		if association == nil && len(associations) < maxUDPSessions {
			backendAddr, resolveErr := net.ResolveUDPAddr("udp", policy.Target)
			if resolveErr == nil {
				backend, dialErr := net.DialUDP("udp", nil, backendAddr)
				if dialErr == nil {
					association = &udpAssociation{key: key, service: service, peerID: peer.NodeID, peerAddr: remote, flowID: flowID, backend: backend}
					association.lastSeen.Store(time.Now().UnixNano())
					associations[key] = association
					go relayUDPResponses(ctx, socket, association, policies, &mu, associations)
				}
			}
		}
		if association != nil {
			association.lastSeen.Store(time.Now().UnixNano())
		}
		mu.Unlock()
		if association != nil {
			_, _ = association.backend.Write(payload)
		}
	}
}

type peerAuthEntry struct {
	peer    record.EndpointRecord
	expires time.Time
}

func cachedUDPIdentity(ctx context.Context, remote *net.UDPAddr, cache map[string]peerAuthEntry, mu *sync.Mutex, authenticate UDPAuthenticator) (record.EndpointRecord, bool) {
	ip := remote.IP.String()
	mu.Lock()
	entry, ok := cache[ip]
	if ok && time.Now().After(entry.expires) {
		delete(cache, ip)
		ok = false
	}
	if !ok && len(cache) >= maxUDPAuthEntries {
		now := time.Now()
		for candidate, old := range cache {
			if now.After(old.expires) {
				delete(cache, candidate)
			}
		}
		if len(cache) >= maxUDPAuthEntries {
			mu.Unlock()
			return record.EndpointRecord{}, false
		}
	}
	mu.Unlock()
	if ok && time.Now().Before(entry.expires) {
		return entry.peer, true
	}
	peer, ok := authenticate(ctx, net.JoinHostPort(ip, strconv.Itoa(remote.Port)))
	if !ok || record.VerifyEndpointRecord(peer, time.Now()) != nil {
		return record.EndpointRecord{}, false
	}
	mu.Lock()
	cache[ip] = peerAuthEntry{peer: peer, expires: time.Now().Add(peerAuthCacheTTL)}
	mu.Unlock()
	return peer, true
}

func relayUDPResponses(ctx context.Context, socket *net.UDPConn, association *udpAssociation, policies func() map[string]ServicePolicy, mu *sync.Mutex, associations map[string]*udpAssociation) {
	defer func() {
		association.Close()
		mu.Lock()
		if associations[association.key] == association {
			delete(associations, association.key)
		}
		mu.Unlock()
	}()
	buffer := make([]byte, 65507)
	for {
		_ = association.backend.SetReadDeadline(time.Now().Add(udpSessionIdle))
		n, err := association.backend.Read(buffer)
		if err != nil || ctx.Err() != nil {
			return
		}
		policy, ok := policies()[association.service]
		if !ok || policy.Target == "" || record.NormalizeServiceProtocol(policy.Protocol) != record.ServiceProtocolUDP || (policy.Private && !policy.Allows(association.peerID)) {
			return
		}
		packet, err := EncodeUDPServiceDatagram(association.service, association.flowID, buffer[:n])
		if err != nil {
			return
		}
		if _, err := socket.WriteToUDP(packet, association.peerAddr); err != nil {
			return
		}
	}
}

type clientUDPFlow struct {
	flowID   uint64
	remote   *net.UDPConn
	lastSeen atomic.Int64
}

func ServeLocalUDPForward(ctx context.Context, localListen string, service record.ServiceRecord, dialer func(context.Context) (net.Conn, error)) error {
	return ServeLocalUDPForwardReady(ctx, localListen, service, dialer, nil)
}

func ServeLocalUDPForwardReady(ctx context.Context, localListen string, service record.ServiceRecord, dialer func(context.Context) (net.Conn, error), ready chan<- net.Addr) error {
	if record.NormalizeServiceProtocol(service.Protocol) != record.ServiceProtocolUDP {
		return errors.New("local UDP forward requires a UDP service record")
	}
	remoteAddress, err := UDPServicePort(service.Address)
	if err != nil {
		return err
	}
	verifiedTunnel, err := dialer(ctx)
	if err != nil {
		return fmt.Errorf("establish verified peer tunnel: %w", err)
	}
	_ = verifiedTunnel.Close()
	remoteAddr, err := net.ResolveUDPAddr("udp6", remoteAddress)
	if err != nil {
		return err
	}
	localAddr, err := net.ResolveUDPAddr("udp", localListen)
	if err != nil {
		return err
	}
	listener, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return fmt.Errorf("listen for local UDP service: %w", err)
	}
	defer listener.Close()
	if ready != nil {
		ready <- listener.LocalAddr()
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	flows := make(map[string]*clientUDPFlow)
	var mu sync.Mutex
	cleanup := time.NewTicker(10 * time.Second)
	defer cleanup.Stop()
	defer func() {
		mu.Lock()
		for key, flow := range flows {
			_ = flow.remote.Close()
			delete(flows, key)
		}
		mu.Unlock()
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-cleanup.C:
			}
			mu.Lock()
			for key, flow := range flows {
				if time.Since(time.Unix(0, flow.lastSeen.Load())) > udpSessionIdle {
					_ = flow.remote.Close()
					delete(flows, key)
				}
			}
			mu.Unlock()
		}
	}()
	buffer := make([]byte, 65507)
	for {
		n, clientAddr, err := listener.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		key := clientAddr.String()
		mu.Lock()
		flow := flows[key]
		if flow == nil {
			if len(flows) >= maxUDPSessions {
				mu.Unlock()
				continue
			}
			remote, dialErr := net.DialUDP("udp6", nil, remoteAddr)
			if dialErr != nil {
				mu.Unlock()
				continue
			}
			var idBytes [8]byte
			if _, err := rand.Read(idBytes[:]); err != nil {
				_ = remote.Close()
				mu.Unlock()
				continue
			}
			flowID := binary.BigEndian.Uint64(idBytes[:])
			if flowID == 0 {
				flowID = 1
			}
			flow = &clientUDPFlow{flowID: flowID, remote: remote}
			flow.lastSeen.Store(time.Now().UnixNano())
			flows[key] = flow
			go relayLocalUDPResponses(ctx, listener, clientAddr, service.ServiceName, flow, &mu, flows, key)
		}
		flow.lastSeen.Store(time.Now().UnixNano())
		mu.Unlock()
		packet, err := EncodeUDPServiceDatagram(service.ServiceName, flow.flowID, buffer[:n])
		if err == nil {
			_, _ = flow.remote.Write(packet)
		}
	}
}

func relayLocalUDPResponses(ctx context.Context, listener *net.UDPConn, clientAddr *net.UDPAddr, service string, flow *clientUDPFlow, mu *sync.Mutex, flows map[string]*clientUDPFlow, key string) {
	defer func() {
		_ = flow.remote.Close()
		mu.Lock()
		if flows[key] == flow {
			delete(flows, key)
		}
		mu.Unlock()
	}()
	buffer := make([]byte, 65507)
	for {
		_ = flow.remote.SetReadDeadline(time.Now().Add(udpSessionIdle))
		n, err := flow.remote.Read(buffer)
		if err != nil || ctx.Err() != nil {
			return
		}
		responseService, flowID, payload, err := DecodeUDPServiceDatagram(buffer[:n])
		if err != nil || responseService != service || flowID != flow.flowID {
			continue
		}
		flow.lastSeen.Store(time.Now().UnixNano())
		if _, err := listener.WriteToUDP(payload, clientAddr); err != nil {
			return
		}
	}
}
