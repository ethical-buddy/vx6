package dht

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/record"
	"github.com/vx6/vx6/internal/strictjson"
)

type PrivateServiceCatalog struct {
	NodeID    string                 `json:"node_id"`
	NodeName  string                 `json:"node_name"`
	PublicKey string                 `json:"public_key"`
	Services  []record.ServiceRecord `json:"services"`
	IssuedAt  string                 `json:"issued_at"`
	ExpiresAt string                 `json:"expires_at"`
	Signature string                 `json:"signature"`
}

func PrivateCatalogKey(nodeName string) string {
	canonical, err := record.NormalizeNodeName(nodeName)
	if err != nil {
		canonical = strings.ToUpper(nodeName)
	}
	return "private-catalog/" + canonical
}

func NewPrivateServiceCatalog(id identity.Identity, nodeName string, services []record.ServiceRecord, ttl time.Duration, now time.Time) (PrivateServiceCatalog, error) {
	canonicalName, err := record.NormalizeNodeName(nodeName)
	if err != nil {
		return PrivateServiceCatalog{}, err
	}
	if ttl <= 0 {
		return PrivateServiceCatalog{}, fmt.Errorf("ttl must be greater than zero")
	}
	if err := id.Validate(); err != nil {
		return PrivateServiceCatalog{}, err
	}
	normalized, err := normalizePrivateCatalogServices(canonicalName, id.NodeID, services, now)
	if err != nil {
		return PrivateServiceCatalog{}, err
	}

	catalog := PrivateServiceCatalog{
		NodeID:    id.NodeID,
		NodeName:  canonicalName,
		PublicKey: base64.StdEncoding.EncodeToString(id.PublicKey),
		Services:  normalized,
		IssuedAt:  now.UTC().Format(time.RFC3339),
		ExpiresAt: now.UTC().Add(ttl).Format(time.RFC3339),
	}
	catalog.Signature = signPrivateCatalog(id, catalog)
	return catalog, nil
}

func VerifyPrivateServiceCatalog(catalog PrivateServiceCatalog, now time.Time) error {
	if catalog.NodeID == "" || catalog.NodeName == "" || catalog.PublicKey == "" || catalog.IssuedAt == "" || catalog.ExpiresAt == "" || catalog.Signature == "" {
		return fmt.Errorf("private catalog missing required fields")
	}
	if err := record.ValidateCanonicalNodeName(catalog.NodeName); err != nil {
		return err
	}
	publicKey, err := base64.StdEncoding.DecodeString(catalog.PublicKey)
	if err != nil {
		return fmt.Errorf("decode catalog public key: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(catalog.Signature)
	if err != nil {
		return fmt.Errorf("decode catalog signature: %w", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("catalog contains invalid public key")
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("catalog contains invalid signature")
	}
	if want := identity.NodeIDFromPublicKey(ed25519.PublicKey(publicKey)); want != catalog.NodeID {
		return fmt.Errorf("catalog node id does not match public key")
	}
	issuedAt, err := time.Parse(time.RFC3339, catalog.IssuedAt)
	if err != nil {
		return fmt.Errorf("parse catalog issued_at: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, catalog.ExpiresAt)
	if err != nil {
		return fmt.Errorf("parse catalog expires_at: %w", err)
	}
	if !expiresAt.After(issuedAt) {
		return fmt.Errorf("catalog expiry must be after issue time")
	}
	if now.UTC().After(expiresAt) {
		return fmt.Errorf("catalog has expired")
	}
	if _, err := normalizePrivateCatalogServices(catalog.NodeName, catalog.NodeID, catalog.Services, now); err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), privateCatalogSigningPayload(catalog), signature) {
		return fmt.Errorf("catalog signature verification failed")
	}
	return nil
}

func DecodePrivateServiceCatalog(raw string, now time.Time) (PrivateServiceCatalog, error) {
	var catalog PrivateServiceCatalog
	if err := strictjson.Decode([]byte(raw), &catalog); err != nil {
		return PrivateServiceCatalog{}, fmt.Errorf("decode private catalog: %w", err)
	}
	if err := VerifyPrivateServiceCatalog(catalog, now); err != nil {
		return PrivateServiceCatalog{}, err
	}
	return catalog, nil
}

func signPrivateCatalog(id identity.Identity, catalog PrivateServiceCatalog) string {
	signature := ed25519.Sign(id.PrivateKey, privateCatalogSigningPayload(catalog))
	return base64.StdEncoding.EncodeToString(signature)
}

func privateCatalogSigningPayload(catalog PrivateServiceCatalog) []byte {
	servicePayload, _ := json.Marshal(catalog.Services)
	return []byte(
		catalog.NodeID + "\n" +
			catalog.NodeName + "\n" +
			catalog.PublicKey + "\n" +
			string(servicePayload) + "\n" +
			catalog.IssuedAt + "\n" +
			catalog.ExpiresAt + "\n",
	)
}

func normalizePrivateCatalogServices(nodeName, nodeID string, services []record.ServiceRecord, now time.Time) ([]record.ServiceRecord, error) {
	out := make([]record.ServiceRecord, 0, len(services))
	seen := map[string]struct{}{}
	for _, svc := range services {
		if err := record.VerifyServiceRecord(svc, now); err != nil {
			return nil, fmt.Errorf("verify catalog service %q: %w", svc.ServiceName, err)
		}
		if svc.NodeName != nodeName || svc.NodeID != nodeID {
			return nil, fmt.Errorf("catalog service %q does not match owner %s/%s", svc.ServiceName, nodeName, nodeID)
		}
		if svc.IsHidden {
			return nil, fmt.Errorf("catalog service %q cannot be hidden", svc.ServiceName)
		}
		if !svc.IsPrivate {
			return nil, fmt.Errorf("catalog service %q must be marked private", svc.ServiceName)
		}
		key := record.FullServiceName(svc.NodeName, svc.ServiceName)
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("duplicate private catalog service %q", key)
		}
		seen[key] = struct{}{}
		out = append(out, svc)
	}
	sort.Slice(out, func(i, j int) bool {
		return record.FullServiceName(out[i].NodeName, out[i].ServiceName) < record.FullServiceName(out[j].NodeName, out[j].ServiceName)
	})
	return out, nil
}
