package dht

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vx6/vx6/internal/record"
)

var (
	ErrConflictingValues        = errors.New("dht lookup returned conflicting values")
	ErrInsufficientConfirmation = errors.New("dht lookup returned insufficient confirmation")
	ErrLookupIncomplete         = errors.New("dht lookup incomplete")
	ErrLookupNotFound           = errors.New("no matching value in reachable peers")
)

type LookupOutcome string

const (
	LookupFound      LookupOutcome = "found_verified"
	LookupNotFound   LookupOutcome = "not_found_reachable"
	LookupIncomplete LookupOutcome = "incomplete"
	LookupConflict   LookupOutcome = "conflict"
)

const (
	minTrustedSupportingSources = 2
	minTrustedASNGroups         = 2
	minTrustedNetworkGroups     = 2
	minTrustedProviderGroups    = 2
	minTrustedConfirmationScore = 4
	minTrustedLookupBranches    = 2
)

type LookupResult struct {
	Outcome           LookupOutcome
	Value             string
	Verified          bool
	SourceCount       int
	ExactMatchCount   int
	QueriedNodes      int
	RejectedValues    int
	ConflictCount     int
	ConflictValues    []string
	PublisherCount    int
	NetworkDiversity  int
	ProviderDiversity int
	ASNDiversity      int
	BranchDiversity   int
	TrustWeight       int
	Version           uint64
}

type validatedValue struct {
	storedRaw              string
	raw                    string
	verified               bool
	family                 string
	fingerprint            string
	issuedAt               time.Time
	expiresAt              time.Time
	version                uint64
	sequenceBased          bool
	originNodeID           string
	publisherNodeID        string
	enveloped              bool
	authoritativePublisher bool
}

type sourceObservation struct {
	nodeID string
	addr   string
	trust  int
	branch int
}

type candidateObservation struct {
	value          validatedValue
	sources        map[string]sourceObservation
	exactSources   map[string]sourceObservation
	providers      map[string]struct{}
	exactProviders map[string]struct{}
	asns           map[string]struct{}
	exactASNs      map[string]struct{}
	networks       map[string]struct{}
	exactNetworks  map[string]struct{}
	branches       map[int]struct{}
	exactBranches  map[int]struct{}
	publishers     map[string]struct{}
	exactWeight    int
}

type lookupCollector struct {
	key        string
	now        time.Time
	verified   map[string]*candidateObservation
	raw        map[string]*candidateObservation
	rejected   int
	conflicted int
}

func newLookupCollector(key string, now time.Time) *lookupCollector {
	return &lookupCollector{
		key:      key,
		now:      now,
		verified: map[string]*candidateObservation{},
		raw:      map[string]*candidateObservation{},
	}
}

func (c *lookupCollector) Observe(source sourceObservation, raw string) {
	if strings.TrimSpace(raw) == "" {
		return
	}
	if source.nodeID == "" {
		source.nodeID = "unknown"
	}
	if source.trust <= 0 {
		source.trust = 1
	}

	value, err := validateLookupValue(c.key, raw, c.now)
	if err != nil {
		c.rejected++
		return
	}

	if value.verified {
		obs, ok := c.verified[value.family]
		if !ok {
			obs = newCandidateObservation(value)
			c.verified[value.family] = obs
		}
		obs.addSource(source)
		if isNewerValue(value, obs.value) {
			obs.value = value
			obs.exactSources = map[string]sourceObservation{}
			obs.exactNetworks = map[string]struct{}{}
			obs.publishers = map[string]struct{}{}
			obs.exactWeight = 0
		}
		if value.fingerprint == obs.value.fingerprint {
			obs.addExactSource(source, value)
		}
		return
	}

	obs, ok := c.raw[value.fingerprint]
	if !ok {
		obs = newCandidateObservation(value)
		c.raw[value.fingerprint] = obs
	}
	obs.addSource(source)
	obs.addExactSource(source, value)
}

func (c *lookupCollector) IsConfirmed() bool {
	if len(c.verified) != 1 {
		return false
	}
	for _, candidate := range c.verified {
		return candidate.confirmed()
	}
	return false
}

func (c *lookupCollector) Resolve(queried int) (LookupResult, error) {
	if len(c.verified) > 0 {
		if len(c.verified) > 1 {
			families := make([]string, 0, len(c.verified))
			conflicts := make([]string, 0, len(c.verified))
			for family := range c.verified {
				families = append(families, family)
			}
			for _, candidate := range c.verified {
				if strings.TrimSpace(candidate.value.raw) != "" {
					conflicts = append(conflicts, candidate.value.raw)
				}
			}
			sort.Strings(families)
			sort.Strings(conflicts)
			return LookupResult{
				Outcome:        LookupConflict,
				Verified:       true,
				QueriedNodes:   queried,
				RejectedValues: c.rejected,
				ConflictCount:  len(families),
				ConflictValues: conflicts,
			}, fmt.Errorf("%w: %s", ErrConflictingValues, strings.Join(families, ", "))
		}
		for _, candidate := range c.verified {
			result := candidate.lookupResult(queried, c.rejected)
			if !candidate.confirmed() {
				result.Outcome = LookupIncomplete
				return result, fmt.Errorf("%w: exact=%d branches=%d asns=%d providers=%d networks=%d weight=%d", ErrInsufficientConfirmation, len(candidate.exactSources), len(candidate.exactBranches), len(candidate.exactASNs), len(candidate.exactProviders), len(candidate.exactNetworks), candidate.exactWeight)
			}
			result.Outcome = LookupFound
			return result, nil
		}
	}

	if len(c.raw) == 0 {
		return LookupResult{
			QueriedNodes:   queried,
			RejectedValues: c.rejected,
			Outcome:        LookupNotFound,
		}, ErrLookupNotFound
	}

	var best *candidateObservation
	conflicts := 0
	conflictValues := make([]string, 0, len(c.raw))
	for _, candidate := range c.raw {
		if strings.TrimSpace(candidate.value.raw) != "" {
			conflictValues = append(conflictValues, candidate.value.raw)
		}
		if best == nil {
			best = candidate
			conflicts = 1
			continue
		}
		switch compareObservationStrength(candidate, best) {
		case 1:
			best = candidate
			conflicts = 1
		case 0:
			conflicts++
		}
	}
	if best == nil {
		return LookupResult{
			QueriedNodes:   queried,
			RejectedValues: c.rejected,
			Outcome:        LookupNotFound,
		}, ErrLookupNotFound
	}
	if conflicts > 1 {
		sort.Strings(conflictValues)
		return LookupResult{
			Outcome:        LookupConflict,
			QueriedNodes:   queried,
			RejectedValues: c.rejected,
			ConflictCount:  conflicts,
			ConflictValues: conflictValues,
		}, fmt.Errorf("%w: conflicting unverified values for key %q", ErrConflictingValues, c.key)
	}

	result := best.lookupResult(queried, c.rejected)
	result.Outcome = LookupFound
	return result, nil
}

func newCandidateObservation(value validatedValue) *candidateObservation {
	return &candidateObservation{
		value:          value,
		sources:        map[string]sourceObservation{},
		exactSources:   map[string]sourceObservation{},
		providers:      map[string]struct{}{},
		exactProviders: map[string]struct{}{},
		asns:           map[string]struct{}{},
		exactASNs:      map[string]struct{}{},
		networks:       map[string]struct{}{},
		exactNetworks:  map[string]struct{}{},
		branches:       map[int]struct{}{},
		exactBranches:  map[int]struct{}{},
		publishers:     map[string]struct{}{},
	}
}

func (c *candidateObservation) addSource(source sourceObservation) {
	if _, ok := c.sources[source.nodeID]; !ok {
		c.sources[source.nodeID] = source
	}
	if provider := source.providerKey(); provider != "" {
		c.providers[provider] = struct{}{}
	}
	if asn := source.asnKey(); asn != "" {
		c.asns[asn] = struct{}{}
	}
	if network := source.networkKey(); network != "" {
		c.networks[network] = struct{}{}
	}
	if source.branch >= 0 {
		c.branches[source.branch] = struct{}{}
	}
}

func (c *candidateObservation) addExactSource(source sourceObservation, value validatedValue) {
	if _, ok := c.exactSources[source.nodeID]; !ok {
		c.exactSources[source.nodeID] = source
		c.exactWeight += source.weightFor(value)
	}
	if provider := source.providerKey(); provider != "" {
		c.exactProviders[provider] = struct{}{}
	}
	if asn := source.asnKey(); asn != "" {
		c.exactASNs[asn] = struct{}{}
	}
	if network := source.networkKey(); network != "" {
		c.exactNetworks[network] = struct{}{}
	}
	if source.branch >= 0 {
		c.exactBranches[source.branch] = struct{}{}
	}
	if value.publisherNodeID != "" {
		c.publishers[value.publisherNodeID] = struct{}{}
	}
}

func (c *candidateObservation) confirmed() bool {
	if !c.value.verified {
		return true
	}
	if len(c.exactSources) < minTrustedSupportingSources {
		return false
	}
	if c.exactWeight < minTrustedConfirmationScore {
		return false
	}
	if !c.onlyLoopbackNetworks() && len(c.exactBranches) < minTrustedLookupBranches {
		return false
	}
	if !c.onlyLoopbackNetworks() {
		if len(c.exactASNs) > 0 {
			if len(c.exactASNs) < minTrustedASNGroups && len(c.exactProviders) < minTrustedProviderGroups {
				return false
			}
		} else if len(c.exactProviders) < minTrustedProviderGroups {
			return false
		}
	}
	if len(c.exactNetworks) >= minTrustedNetworkGroups {
		return true
	}
	return c.onlyLoopbackNetworks()
}

func (c *candidateObservation) onlyLoopbackNetworks() bool {
	if len(c.exactNetworks) == 0 {
		return false
	}
	for network := range c.exactNetworks {
		if !strings.HasPrefix(network, "loopback:") {
			return false
		}
	}
	return true
}

func (c *candidateObservation) lookupResult(queried, rejected int) LookupResult {
	return LookupResult{
		Value:             c.value.raw,
		Verified:          c.value.verified,
		SourceCount:       len(c.sources),
		ExactMatchCount:   len(c.exactSources),
		QueriedNodes:      queried,
		RejectedValues:    rejected,
		PublisherCount:    len(c.publishers),
		NetworkDiversity:  len(c.exactNetworks),
		ProviderDiversity: len(c.exactProviders),
		ASNDiversity:      len(c.exactASNs),
		BranchDiversity:   len(c.exactBranches),
		TrustWeight:       c.exactWeight,
		Version:           c.value.version,
	}
}

func (s sourceObservation) providerKey() string {
	host := s.addr
	if parsedHost, _, err := net.SplitHostPort(s.addr); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	if ip.IsLoopback() {
		return "loopback:" + ip.String()
	}
	if v4 := ip.To4(); v4 != nil {
		return "provider4:" + v4.Mask(net.CIDRMask(16, 32)).String()
	}
	return "provider6:" + ip.Mask(net.CIDRMask(32, 128)).String()
}

func (s sourceObservation) asnKey() string {
	asn, ok := ResolveASNForAddr(s.addr)
	if !ok {
		return ""
	}
	return "asn:" + asn
}

func (s sourceObservation) networkKey() string {
	host := s.addr
	if parsedHost, _, err := net.SplitHostPort(s.addr); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	if ip.IsLoopback() {
		return "loopback:" + ip.String()
	}
	if v4 := ip.To4(); v4 != nil {
		return "ipv4:" + v4.Mask(net.CIDRMask(24, 32)).String()
	}
	return "ipv6:" + ip.Mask(net.CIDRMask(64, 128)).String()
}

func (s sourceObservation) weightFor(value validatedValue) int {
	weight := s.trust
	if value.enveloped {
		weight++
	}
	if value.authoritativePublisher {
		weight++
	}
	return weight
}

func validateLookupValue(key, raw string, now time.Time) (validatedValue, error) {
	env, ok, err := maybeDecodeEnvelope(raw)
	if err != nil {
		return validatedValue{}, err
	}
	if ok {
		if err := verifyEnvelope(key, env, now); err != nil {
			return validatedValue{}, err
		}
		value, err := validateInnerLookupValue(key, env.Value, now)
		if err != nil {
			return validatedValue{}, err
		}
		value.storedRaw = raw
		value.publisherNodeID = env.PublisherNodeID
		value.enveloped = true
		if value.verified {
			if env.OriginNodeID != value.originNodeID {
				return validatedValue{}, fmt.Errorf("envelope origin %q does not match record origin %q", env.OriginNodeID, value.originNodeID)
			}
			if env.Version != value.version {
				return validatedValue{}, fmt.Errorf("envelope version %d does not match record version %d", env.Version, value.version)
			}
			if env.IssuedAt != value.issuedAt.UTC().Format(time.RFC3339) {
				return validatedValue{}, fmt.Errorf("envelope issued_at does not match wrapped record")
			}
			if env.ExpiresAt != value.expiresAt.UTC().Format(time.RFC3339) {
				return validatedValue{}, fmt.Errorf("envelope expires_at does not match wrapped record")
			}
		}
		value.authoritativePublisher = value.originNodeID != "" && value.publisherNodeID == value.originNodeID
		return value, nil
	}
	return validateInnerLookupValue(key, raw, now)
}

func validateInnerLookupValue(key, raw string, now time.Time) (validatedValue, error) {
	switch {
	case strings.HasPrefix(key, "node/name/"):
		var rec record.EndpointRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			return validatedValue{}, fmt.Errorf("decode endpoint record: %w", err)
		}
		if err := record.VerifyEndpointRecord(rec, now); err != nil {
			return validatedValue{}, err
		}
		if NodeNameKey(rec.NodeName) != key {
			return validatedValue{}, fmt.Errorf("endpoint record name %q does not match name lookup key", rec.NodeName)
		}
		issuedAt, expiresAt, _, err := recordTimes(rec.IssuedAt, rec.ExpiresAt)
		if err != nil {
			return validatedValue{}, err
		}
		version := record.EndpointRecordSequenceVersion(rec)
		return validatedValue{
			storedRaw:     raw,
			raw:           raw,
			verified:      true,
			family:        "endpoint:" + rec.NodeID,
			fingerprint:   record.Fingerprint(rec),
			issuedAt:      issuedAt,
			expiresAt:     expiresAt,
			version:       version,
			sequenceBased: rec.Version >= 2,
			originNodeID:  rec.NodeID,
		}, nil
	case strings.HasPrefix(key, "node/id/"):
		want := strings.TrimPrefix(key, "node/id/")
		var rec record.EndpointRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			return validatedValue{}, fmt.Errorf("decode endpoint record: %w", err)
		}
		if err := record.VerifyEndpointRecord(rec, now); err != nil {
			return validatedValue{}, err
		}
		if rec.NodeID != want {
			return validatedValue{}, fmt.Errorf("endpoint record node id %q does not match key %q", rec.NodeID, want)
		}
		issuedAt, expiresAt, _, err := recordTimes(rec.IssuedAt, rec.ExpiresAt)
		if err != nil {
			return validatedValue{}, err
		}
		version := record.EndpointRecordSequenceVersion(rec)
		return validatedValue{
			storedRaw:     raw,
			raw:           raw,
			verified:      true,
			family:        "endpoint:" + rec.NodeID,
			fingerprint:   record.Fingerprint(rec),
			issuedAt:      issuedAt,
			expiresAt:     expiresAt,
			version:       version,
			sequenceBased: rec.Version >= 2,
			originNodeID:  rec.NodeID,
		}, nil
	case strings.HasPrefix(key, "service/"):
		want := strings.TrimPrefix(key, "service/")
		var rec record.ServiceRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			return validatedValue{}, fmt.Errorf("decode service record: %w", err)
		}
		if err := record.VerifyServiceRecord(rec, now); err != nil {
			return validatedValue{}, err
		}
		if rec.IsPrivate {
			return validatedValue{}, fmt.Errorf("private service %q cannot be stored in public service keyspace", want)
		}
		if record.FullServiceName(rec.NodeName, rec.ServiceName) != want {
			return validatedValue{}, fmt.Errorf("service record name %q does not match key %q", record.FullServiceName(rec.NodeName, rec.ServiceName), want)
		}
		issuedAt, expiresAt, version, err := recordTimes(rec.IssuedAt, rec.ExpiresAt)
		if err != nil {
			return validatedValue{}, err
		}
		return validatedValue{
			storedRaw:    raw,
			raw:          raw,
			verified:     true,
			family:       "service:" + rec.NodeID + ":" + want,
			fingerprint:  serviceFingerprint(rec),
			issuedAt:     issuedAt,
			expiresAt:    expiresAt,
			version:      version,
			originNodeID: rec.NodeID,
		}, nil
	case strings.HasPrefix(key, "private-catalog/"):
		want := strings.TrimPrefix(key, "private-catalog/")
		catalog, err := DecodePrivateServiceCatalog(raw, now)
		if err != nil {
			return validatedValue{}, err
		}
		if catalog.NodeName != want {
			return validatedValue{}, fmt.Errorf("private catalog name %q does not match key %q", catalog.NodeName, want)
		}
		issuedAt, expiresAt, version, err := recordTimes(catalog.IssuedAt, catalog.ExpiresAt)
		if err != nil {
			return validatedValue{}, err
		}
		return validatedValue{
			storedRaw:    raw,
			raw:          raw,
			verified:     true,
			family:       "private-catalog:" + catalog.NodeID + ":" + want,
			fingerprint:  rawFingerprint(catalog.Signature + "\n" + catalog.IssuedAt + "\n" + catalog.ExpiresAt),
			issuedAt:     issuedAt,
			expiresAt:    expiresAt,
			version:      version,
			originNodeID: catalog.NodeID,
		}, nil
	case strings.HasPrefix(key, "hidden/"):
		want := strings.TrimPrefix(key, "hidden/")
		var rec record.ServiceRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			return validatedValue{}, fmt.Errorf("decode hidden service record: %w", err)
		}
		if err := record.VerifyServiceRecord(rec, now); err != nil {
			return validatedValue{}, err
		}
		if !rec.IsHidden || rec.Alias != want {
			return validatedValue{}, fmt.Errorf("hidden service alias %q does not match key %q", rec.Alias, want)
		}
		issuedAt, expiresAt, version, err := recordTimes(rec.IssuedAt, rec.ExpiresAt)
		if err != nil {
			return validatedValue{}, err
		}
		return validatedValue{
			storedRaw:    raw,
			raw:          raw,
			verified:     true,
			family:       "hidden:" + rec.NodeID + ":" + want,
			fingerprint:  serviceFingerprint(rec),
			issuedAt:     issuedAt,
			expiresAt:    expiresAt,
			version:      version,
			originNodeID: rec.NodeID,
		}, nil
	case strings.HasPrefix(key, "hidden-desc/v1/"):
		if _, err := parseHiddenDescriptorEpoch(key); err != nil {
			return validatedValue{}, err
		}
		if desc, err := parseHiddenDescriptor(raw); err == nil {
			issuedAt, expiresAt, version, err := recordTimes(desc.IssuedAt, desc.ExpiresAt)
			if err != nil {
				return validatedValue{}, err
			}
			return validatedValue{
				storedRaw:    raw,
				raw:          raw,
				verified:     true,
				family:       "hidden:" + desc.NodeID + ":" + desc.ServiceTag,
				fingerprint:  hiddenDescriptorFingerprint(desc),
				issuedAt:     issuedAt,
				expiresAt:    expiresAt,
				version:      version,
				originNodeID: desc.NodeID,
			}, nil
		}

		var rec record.ServiceRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			return validatedValue{}, fmt.Errorf("decode hidden service descriptor: %w", err)
		}
		if err := record.VerifyServiceRecord(rec, now); err != nil {
			return validatedValue{}, err
		}
		if !rec.IsHidden || rec.Alias == "" {
			return validatedValue{}, fmt.Errorf("hidden descriptor must wrap a hidden service with alias")
		}
		epoch, _ := parseHiddenDescriptorEpoch(key)
		if expected := hiddenServiceKeyForRefEpoch(HiddenLookupRef{Alias: rec.Alias}, epoch); expected != key {
			return validatedValue{}, fmt.Errorf("hidden descriptor key %q does not match alias-derived blinded key %q", key, expected)
		}
		issuedAt, expiresAt, version, err := recordTimes(rec.IssuedAt, rec.ExpiresAt)
		if err != nil {
			return validatedValue{}, err
		}
		return validatedValue{
			storedRaw:    raw,
			raw:          raw,
			verified:     true,
			family:       "hidden:" + rec.NodeID + ":" + hiddenServiceTag(rec),
			fingerprint:  serviceFingerprint(rec),
			issuedAt:     issuedAt,
			expiresAt:    expiresAt,
			version:      version,
			originNodeID: rec.NodeID,
		}, nil
	default:
		return validatedValue{
			storedRaw:   raw,
			raw:         raw,
			fingerprint: rawFingerprint(raw),
		}, nil
	}
}

func chooseStoredValue(key, existing, incoming string, now time.Time) (string, bool, validatedValue, validatedValue, error) {
	if existing == "" {
		incomingValue, err := validateLookupValue(key, incoming, now)
		if err != nil {
			return "", false, validatedValue{}, validatedValue{}, err
		}
		return incoming, true, validatedValue{}, incomingValue, nil
	}

	incomingValue, err := validateLookupValue(key, incoming, now)
	if err != nil {
		return "", false, validatedValue{}, validatedValue{}, err
	}
	existingValue, err := validateLookupValue(key, existing, now)
	if err != nil {
		return incoming, true, validatedValue{}, incomingValue, nil
	}

	if !incomingValue.verified {
		if existing == incoming {
			return existing, false, existingValue, incomingValue, nil
		}
		return incoming, true, existingValue, incomingValue, nil
	}
	if !existingValue.verified {
		return incoming, true, existingValue, incomingValue, nil
	}
	if existingValue.family != incomingValue.family {
		return existing, false, existingValue, incomingValue, fmt.Errorf("%w: existing=%s incoming=%s", ErrConflictingValues, existingValue.family, incomingValue.family)
	}
	if incomingValue.fingerprint == existingValue.fingerprint {
		return existing, false, existingValue, incomingValue, nil
	}
	if isNewerValue(incomingValue, existingValue) {
		return incoming, true, existingValue, incomingValue, nil
	}
	return existing, false, existingValue, incomingValue, nil
}

func compareObservationStrength(left, right *candidateObservation) int {
	if len(left.exactSources) > len(right.exactSources) {
		return 1
	}
	if len(left.exactSources) < len(right.exactSources) {
		return -1
	}
	if left.exactWeight > right.exactWeight {
		return 1
	}
	if left.exactWeight < right.exactWeight {
		return -1
	}
	if len(left.exactProviders) > len(right.exactProviders) {
		return 1
	}
	if len(left.exactProviders) < len(right.exactProviders) {
		return -1
	}
	if len(left.exactNetworks) > len(right.exactNetworks) {
		return 1
	}
	if len(left.exactNetworks) < len(right.exactNetworks) {
		return -1
	}
	if left.value.fingerprint < right.value.fingerprint {
		return 1
	}
	if left.value.fingerprint > right.value.fingerprint {
		return -1
	}
	return 0
}

func isNewerValue(candidate, current validatedValue) bool {
	if candidate.version > current.version {
		return true
	}
	if candidate.version < current.version {
		return false
	}
	if candidate.sequenceBased && current.sequenceBased {
		return candidate.fingerprint > current.fingerprint
	}
	if candidate.issuedAt.After(current.issuedAt) {
		return true
	}
	if candidate.issuedAt.Before(current.issuedAt) {
		return false
	}
	return candidate.fingerprint > current.fingerprint
}

func recordTimes(issuedAtRaw, expiresAtRaw string) (time.Time, time.Time, uint64, error) {
	issuedAt, err := time.Parse(time.RFC3339, issuedAtRaw)
	if err != nil {
		return time.Time{}, time.Time{}, 0, fmt.Errorf("parse issued_at: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresAtRaw)
	if err != nil {
		return time.Time{}, time.Time{}, 0, fmt.Errorf("parse expires_at: %w", err)
	}
	return issuedAt, expiresAt, uint64(issuedAt.UTC().Unix()), nil
}

func rawFingerprint(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

func serviceFingerprint(rec record.ServiceRecord) string {
	sum := sha256.Sum256([]byte(rec.Signature + "\n" + rec.IssuedAt + "\n" + rec.ExpiresAt))
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

func parseHiddenDescriptorEpoch(key string) (int64, error) {
	parts := strings.Split(key, "/")
	if len(parts) != 4 || parts[0] != "hidden-desc" || parts[1] != "v1" || parts[2] == "" || parts[3] == "" {
		return 0, fmt.Errorf("invalid hidden descriptor key %q", key)
	}
	epoch, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || epoch < 0 {
		return 0, fmt.Errorf("invalid hidden descriptor epoch in key %q", key)
	}
	return epoch, nil
}
