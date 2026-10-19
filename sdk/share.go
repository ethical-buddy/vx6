package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vx6/vx6/internal/dht"
	"github.com/vx6/vx6/internal/discovery"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
	"github.com/vx6/vx6/internal/secure"
	"github.com/vx6/vx6/internal/transfer"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

type PeerInvite struct {
	NodeName string `json:"node_name"`
	NodeID   string `json:"node_id"`
	Address  string `json:"address"`
}

type SharedFile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	UpdatedAt   string `json:"updated_at"`
}

type ShareCatalog struct {
	NodeID    string       `json:"node_id"`
	NodeName  string       `json:"node_name"`
	Address   string       `json:"address"`
	UpdatedAt string       `json:"updated_at"`
	Files     []SharedFile `json:"files"`
}

const catalogKeyPrefix = "vx6share/catalog/"

func (c *Client) DHTPut(ctx context.Context, key string, payload []byte) error {
	cfg, err := c.store.Load()
	if err != nil {
		return err
	}
	client, err := c.newDHTClient(cfg)
	if err != nil {
		return err
	}
	_, err = client.MaintainReplicas(ctx, key, string(payload))
	return err
}

func (c *Client) DHTGet(ctx context.Context, key string) ([]byte, error) {
	cfg, err := c.store.Load()
	if err != nil {
		return nil, err
	}
	client, err := c.newDHTClient(cfg)
	if err != nil {
		return nil, err
	}
	value, err := client.RecursiveFindValue(ctx, key)
	if err != nil {
		return nil, err
	}
	return []byte(value), nil
}

func (c *Client) BuildInvite() (PeerInvite, string, error) {
	cfg, err := c.store.Load()
	if err != nil {
		return PeerInvite{}, "", err
	}
	idStore, err := identity.NewStoreForConfig(c.store.Path())
	if err != nil {
		return PeerInvite{}, "", err
	}
	id, err := idStore.Load()
	if err != nil {
		return PeerInvite{}, "", err
	}
	invite := PeerInvite{
		NodeName: cfg.Node.Name,
		NodeID:   id.NodeID,
		Address:  cfg.Node.AdvertiseAddr,
	}
	raw, err := json.Marshal(invite)
	if err != nil {
		return PeerInvite{}, "", err
	}
	link := "vx6share://peer/" + base64.RawURLEncoding.EncodeToString(raw)
	return invite, link, nil
}

func DecodeInvite(link string) (PeerInvite, error) {
	const prefix = "vx6share://peer/"
	if !strings.HasPrefix(strings.TrimSpace(link), prefix) {
		return PeerInvite{}, fmt.Errorf("invalid invite link")
	}
	raw := strings.TrimPrefix(strings.TrimSpace(link), prefix)
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return PeerInvite{}, err
	}
	var invite PeerInvite
	if err := json.Unmarshal(data, &invite); err != nil {
		return PeerInvite{}, err
	}
	if invite.NodeID == "" || invite.Address == "" {
		return PeerInvite{}, fmt.Errorf("invite missing node id or address")
	}
	return invite, nil
}

func (c *Client) PublishCatalog(ctx context.Context, catalog ShareCatalog) error {
	if catalog.NodeID == "" {
		return fmt.Errorf("catalog node id is required")
	}
	cfg, err := c.store.Load()
	if err != nil {
		return err
	}
	client, err := c.newDHTClient(cfg)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(catalog)
	if err != nil {
		return err
	}
	_, err = client.MaintainReplicas(ctx, catalogKeyPrefix+catalog.NodeID, string(raw))
	return err
}

func (c *Client) FetchCatalog(ctx context.Context, nodeID string) (ShareCatalog, error) {
	cfg, err := c.store.Load()
	if err != nil {
		return ShareCatalog{}, err
	}
	client, err := c.newDHTClient(cfg)
	if err != nil {
		return ShareCatalog{}, err
	}
	raw, err := client.RecursiveFindValue(ctx, catalogKeyPrefix+nodeID)
	if err != nil {
		return ShareCatalog{}, err
	}
	var cat ShareCatalog
	if err := json.Unmarshal([]byte(raw), &cat); err != nil {
		return ShareCatalog{}, err
	}
	return cat, nil
}

func (c *Client) SendFileWithProgress(ctx context.Context, peerAddr, filePath string, onProgress func(sent int64, total int64)) error {
	if err := transfer.ValidateIPv6Address(peerAddr); err != nil {
		return err
	}
	cfg, err := c.store.Load()
	if err != nil {
		return err
	}
	idStore, err := identity.NewStoreForConfig(c.store.Path())
	if err != nil {
		return err
	}
	id, err := idStore.Load()
	if err != nil {
		return err
	}
	registry, err := discovery.NewRegistry(filepath.Join(cfg.Node.DataDir, "registry.json"))
	if err != nil {
		return err
	}
	ctx, err = c.guardedPeerContext(ctx, cfg, id, registry)
	if err != nil {
		return err
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	total := info.Size()
	conn, err := vxtransport.DialContext(ctx, vxtransport.ModeAuto, peerAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := proto.WriteHeader(conn, proto.KindFileTransfer); err != nil {
		return err
	}
	secureConn, err := secure.Client(conn, proto.KindFileTransfer, id)
	if err != nil {
		return err
	}
	meta := map[string]any{
		"node_name": cfg.Node.Name,
		"file_name": filepath.Base(filePath),
		"file_size": total,
	}
	metaRaw, _ := json.Marshal(meta)
	if err := proto.WriteLengthPrefixed(secureConn, metaRaw); err != nil {
		return err
	}
	resumeRaw, err := proto.ReadLengthPrefixed(secureConn, 4096)
	if err != nil {
		return err
	}
	var resume struct {
		Offset int64  `json:"offset"`
		Denied string `json:"denied,omitempty"`
	}
	if err := json.Unmarshal(resumeRaw, &resume); err != nil {
		return err
	}
	if resume.Denied != "" {
		return fmt.Errorf("transfer rejected: %s", resume.Denied)
	}
	if resume.Offset > 0 {
		if _, err := file.Seek(resume.Offset, io.SeekStart); err != nil {
			return err
		}
	}
	buf := make([]byte, 64*1024)
	sent := resume.Offset
	if onProgress != nil {
		onProgress(sent, total)
	}
	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			if _, err := secureConn.Write(buf[:n]); err != nil {
				return err
			}
			sent += int64(n)
			if onProgress != nil {
				onProgress(sent, total)
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return readErr
		}
	}
	return nil
}

func BuildSharedFile(path, description string) (SharedFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return SharedFile{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return SharedFile{}, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return SharedFile{}, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	idRaw := sha256.Sum256([]byte(path + "\n" + sum))
	return SharedFile{
		ID:          base64.RawURLEncoding.EncodeToString(idRaw[:12]),
		Name:        filepath.Base(path),
		Description: description,
		Size:        info.Size(),
		SHA256:      sum,
		UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (c *Client) ResolveNode(ctx context.Context, name string) (record.EndpointRecord, error) {
	cfg, err := c.store.Load()
	if err != nil {
		return record.EndpointRecord{}, err
	}
	client, err := c.newDHTClient(cfg)
	if err != nil {
		return record.EndpointRecord{}, err
	}
	result, err := client.RecursiveFindValueDetailed(ctx, dht.NodeNameKey(name))
	if err != nil {
		return record.EndpointRecord{}, err
	}
	var rec record.EndpointRecord
	if err := json.Unmarshal([]byte(result.Value), &rec); err != nil {
		return record.EndpointRecord{}, err
	}
	return rec, nil
}

// ParsePercentPort validates listen addr style for helper UIs.
func ParsePercentPort(addr string) error {
	_, _, err := net.SplitHostPort(addr)
	return err
}
