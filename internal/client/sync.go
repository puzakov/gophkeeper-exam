package client

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/puzakov/gophkeeper-exam/internal/model"
	protov1 "github.com/puzakov/gophkeeper-exam/internal/proto/v1"
)

// SyncResult holds the outcome of a sync operation.
type SyncResult struct {
	Updated   []*protov1.Secret
	Deleted   []string
	Conflicts []*protov1.SyncVersion
}

// syncedSecret is a decrypted secret with its payload and metadata.
type syncedSecret struct {
	Secret  *model.Secret
	Payload any
	Meta    model.Metadata
}

// Sync pulls the latest state from the server and returns deltas.
func (c *GophKeeperClient) Sync(ctx context.Context, clientVersions map[string]int64, clientDeleted []string) (*SyncResult, error) {
	var versions []*protov1.SyncVersion
	for id, ver := range clientVersions {
		versions = append(versions, (&protov1.SyncVersion_builder{
			SecretId: id,
			Version:  ver,
		}).Build())
	}

	resp, err := c.SyncSvc.SyncSecrets(c.AuthContext(ctx), (&protov1.SyncSecretsRequest_builder{
		ClientVersions: versions,
		ClientDeleted:  clientDeleted,
	}).Build())
	if err != nil {
		c.applyStatusFromError(err)
		return nil, fmt.Errorf("sync: %w", err)
	}

	c.applyStatusFromError(nil)

	// Refresh the local cache with server state (encrypted blobs only).
	if c.local != nil {
		var upserts []*model.Secret
		for _, p := range resp.GetUpdatedSecrets() {
			upserts = append(upserts, protoToModelSecret(p))
		}
		if len(upserts) > 0 {
			_ = c.local.SaveSecrets(upserts)
		}
		for _, id := range resp.GetDeletedIds() {
			if sec, err := c.local.LoadSecret(id); err == nil {
				now := time.Now()
				sec.DeletedAt = &now
				_ = c.local.SaveSecret(sec)
			}
		}
	}

	return &SyncResult{
		Updated:   resp.GetUpdatedSecrets(),
		Deleted:   resp.GetDeletedIds(),
		Conflicts: resp.GetConflicts(),
	}, nil
}

// SyncAndDecrypt pulls updates and decrypts them.
func (c *GophKeeperClient) SyncAndDecrypt(ctx context.Context, clientVersions map[string]int64, clientDeleted []string) ([]*syncedSecret, error) {
	result, err := c.Sync(ctx, clientVersions, clientDeleted)
	if err != nil {
		return nil, err
	}

	var out []*syncedSecret
	for _, s := range result.Updated {
		sec, payload, meta, err := c.decryptProtoSecret(s)
		if err != nil {
			continue
		}
		out = append(out, &syncedSecret{
			Secret:  sec,
			Payload: payload,
			Meta:    meta,
		})
	}

	for _, id := range result.Deleted {
		uid, _ := uuid.Parse(id)
		out = append(out, &syncedSecret{
			Secret:  &model.Secret{ID: uid},
			Payload: nil,
			Meta:    nil,
		})
	}

	return out, nil
}
