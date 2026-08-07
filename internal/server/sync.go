package server

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	protov1 "github.com/puzakov/gophkeeper-exam/internal/proto/v1"
	"github.com/puzakov/gophkeeper-exam/internal/service"
)

// SyncServer implements the proto SyncService.
type SyncServer struct {
	protov1.UnimplementedSyncServiceServer
	sync *service.SyncService
}

// NewSyncServer creates a new SyncServer.
func NewSyncServer(sync *service.SyncService) *SyncServer {
	return &SyncServer{sync: sync}
}

// SyncSecrets computes the diff between client versions and server state.
func (s *SyncServer) SyncSecrets(ctx context.Context, req *protov1.SyncSecretsRequest) (*protov1.SyncSecretsResponse, error) {
	userID, err := parseUserID(ctx)
	if err != nil {
		return nil, err
	}

	clientVersions := make(map[string]int64, len(req.GetClientVersions()))
	for _, v := range req.GetClientVersions() {
		clientVersions[v.GetSecretId()] = v.GetVersion()
	}

	diff, err := s.sync.Diff(ctx, userID, clientVersions, req.GetClientDeleted())
	if err != nil {
		return nil, status.Error(codes.Internal, "sync failed")
	}

	resp := &protov1.SyncSecretsResponse{
		DeletedIds: diff.DeletedIDs,
	}

	for _, sec := range diff.Updated {
		resp.UpdatedSecrets = append(resp.UpdatedSecrets, modelToProto(&sec))
	}

	for sid, ver := range diff.Conflicts {
		resp.Conflicts = append(resp.Conflicts, &protov1.SyncVersion{
			SecretId: sid,
			Version:  ver,
		})
	}

	for sid, ver := range diff.ServerVersions {
		resp.ServerVersions = append(resp.ServerVersions, &protov1.SyncVersion{
			SecretId: sid,
			Version:  ver,
		})
	}

	return resp, nil
}
