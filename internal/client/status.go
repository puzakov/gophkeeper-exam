package client

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/puzakov/gophkeeper-exam/internal/model"
	protov1 "github.com/puzakov/gophkeeper-exam/internal/proto/v1"
)

// probeInterval is how often the background monitor checks connectivity.
const probeInterval = 30 * time.Second

// OnlineStatus tracks whether the server is reachable. Safe for concurrent use.
type OnlineStatus struct {
	mu      sync.RWMutex
	online  bool
	checked bool // false until the first probe completes
}

// IsOnline reports the last known server reachability.
func (s *OnlineStatus) IsOnline() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.online
}

// WasChecked reports whether at least one connectivity check has completed.
func (s *OnlineStatus) WasChecked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.checked
}

func (s *OnlineStatus) setOnline(v bool) {
	s.mu.Lock()
	s.online = v
	s.checked = true
	s.mu.Unlock()
}

// StartConnectivityMonitor launches a background goroutine that periodically
// syncs with the server. On success it refreshes the local cache (using the
// cache's version map) and marks the client online; on failure it marks it
// offline. The goroutine stops when ctx is cancelled or the client closes.
func (c *GophKeeperClient) StartConnectivityMonitor(ctx context.Context) {
	// Only one monitor per client instance.
	c.monitorOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(probeInterval)
			defer ticker.Stop()

			// Probe once immediately.
			c.probe()

			for {
				select {
				case <-ctx.Done():
					return
				case <-c.closed:
					return
				case <-ticker.C:
					c.probe()
				}
			}
		}()
	})
}

// probe performs one connectivity check and cache refresh.
func (c *GophKeeperClient) probe() {
	if c.local == nil || !c.HasKeyMaterial() {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Build the version map from the local cache for incremental sync.
	versions := map[string]int64{}
	if cached, err := c.local.LoadSecrets(); err == nil {
		for _, s := range cached {
			if s.DeletedAt == nil {
				versions[s.ID.String()] = s.Version
			}
		}
	}

	result, err := c.Sync(ctx, versions, nil)
	if err != nil {
		c.status.setOnline(false)
		return
	}

	// Refresh cache with server state (encrypted blobs only — no DEK needed).
	var upserts []*model.Secret
	for _, p := range result.Updated {
		upserts = append(upserts, protoToModelSecret(p))
	}
	if len(upserts) > 0 {
		_ = c.local.SaveSecrets(upserts)
	}

	for _, id := range result.Deleted {
		if sec, err := c.local.LoadSecret(id); err == nil && sec != nil {
			now := time.Now()
			sec.DeletedAt = &now
			_ = c.local.SaveSecret(sec)
		}
	}

	c.status.setOnline(true)
}

// protoToModelSecret converts a proto Secret to the domain model.
func protoToModelSecret(p *protov1.Secret) *model.Secret {
	id, _ := uuid.Parse(p.GetId())
	return &model.Secret{
		ID:                id,
		Type:              model.SecretType(p.GetType()),
		EncryptedData:     p.GetEncryptedData(),
		EncryptedMetadata: p.GetEncryptedMetadata(),
		Comment:           p.GetComment(),
		Version:           p.GetVersion(),
		CreatedAt:         time.Unix(p.GetCreatedAt(), 0),
		UpdatedAt:         time.Unix(p.GetUpdatedAt(), 0),
	}
}
