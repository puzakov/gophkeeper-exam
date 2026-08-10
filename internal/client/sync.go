package client

import (
	"fmt"

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
func (c *GophKeeperClient) Sync(clientVersions map[string]int64, clientDeleted []string) (*SyncResult, error) {
	var versions []*protov1.SyncVersion
	for id, ver := range clientVersions {
		versions = append(versions, &protov1.SyncVersion{
			SecretId: id,
			Version:  ver,
		})
	}

	resp, err := c.SyncSvc.SyncSecrets(c.AuthContext(), &protov1.SyncSecretsRequest{
		ClientVersions: versions,
		ClientDeleted:  clientDeleted,
	})
	if err != nil {
		return nil, fmt.Errorf("sync: %w", err)
	}

	return &SyncResult{
		Updated:   resp.GetUpdatedSecrets(),
		Deleted:   resp.GetDeletedIds(),
		Conflicts: resp.GetConflicts(),
	}, nil
}

// SyncAndDecrypt pulls updates and decrypts them.
func (c *GophKeeperClient) SyncAndDecrypt(clientVersions map[string]int64, clientDeleted []string) ([]*syncedSecret, error) {
	result, err := c.Sync(clientVersions, clientDeleted)
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
