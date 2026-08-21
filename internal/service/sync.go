package service

import (
	"context"

	"github.com/google/uuid"

	"github.com/puzakov/gophkeeper-exam/internal/model"
	"github.com/puzakov/gophkeeper-exam/internal/storage"
)

// SyncService computes diffs between client-side version maps and server state.
type SyncService struct {
	secrets storage.SecretRepository
}

// NewSyncService creates a new SyncService.
func NewSyncService(secrets storage.SecretRepository) *SyncService {
	return &SyncService{secrets: secrets}
}

// DiffResult holds the result of comparing client versions with server state.
type DiffResult struct {
	Updated        []model.Secret
	DeletedIDs     []string
	Conflicts      map[string]int64
	ServerVersions map[string]int64
}

// Diff compares the client's version map with the server's current state.
func (s *SyncService) Diff(ctx context.Context, userID uuid.UUID,
	clientVersions map[string]int64, clientDeleted []string) (*DiffResult, error) {

	all, err := s.secrets.ListForSync(ctx, userID)
	if err != nil {
		return nil, err
	}

	result := &DiffResult{
		ServerVersions: make(map[string]int64, len(all)),
		Conflicts:      make(map[string]int64),
	}

	clientDeletedSet := make(map[string]bool, len(clientDeleted))
	for _, id := range clientDeleted {
		clientDeletedSet[id] = true
	}

	for _, srv := range all {
		sid := srv.ID.String()
		isTombstone := srv.DeletedAt != nil

		result.ServerVersions[sid] = srv.Version

		clientVersion, clientHas := clientVersions[sid]
		clientMarkedDeleted := clientDeletedSet[sid]

		switch {
		case isTombstone && !clientMarkedDeleted:
			// Server deleted — tell client.
			result.DeletedIDs = append(result.DeletedIDs, sid)

		case !isTombstone && !clientHas:
			// Client doesn't have this secret — send it.
			result.Updated = append(result.Updated, srv)

		case !isTombstone && clientHas && srv.Version > clientVersion:
			// Server has newer version — send it.
			result.Updated = append(result.Updated, srv)

		case !isTombstone && clientHas && clientVersion > srv.Version:
			// Client claims a newer version — conflict.
			result.Conflicts[sid] = srv.Version

		case isTombstone && clientMarkedDeleted:
			// Both deleted — nothing to do.
		}
	}

	return result, nil
}
