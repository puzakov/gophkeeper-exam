package server

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/puzakov/gophkeeper-exam/internal/model"
	protov1 "github.com/puzakov/gophkeeper-exam/internal/proto/v1"
	"github.com/puzakov/gophkeeper-exam/internal/service"
)

// SecretServer implements the proto SecretService.
type SecretServer struct {
	protov1.UnimplementedSecretServiceServer
	secrets *service.SecretService
}

// NewSecretServer creates a new SecretServer.
func NewSecretServer(secrets *service.SecretService) *SecretServer {
	return &SecretServer{secrets: secrets}
}

// CreateSecret stores a new encrypted secret.
func (s *SecretServer) CreateSecret(ctx context.Context, req *protov1.CreateSecretRequest) (*protov1.CreateSecretResponse, error) {
	userID, err := parseUserID(ctx)
	if err != nil {
		return nil, err
	}

	secret, err := s.secrets.Create(ctx, userID,
		protoToModelType(req.GetType()),
		req.GetEncryptedData(),
		req.GetEncryptedMetadata(),
		req.GetComment(),
	)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &protov1.CreateSecretResponse{
		Id:      secret.ID.String(),
		Version: secret.Version,
	}, nil
}

// GetSecret returns a single secret.
func (s *SecretServer) GetSecret(ctx context.Context, req *protov1.GetSecretRequest) (*protov1.GetSecretResponse, error) {
	userID, err := parseUserID(ctx)
	if err != nil {
		return nil, err
	}

	secretID, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid secret id")
	}

	secret, err := s.secrets.Get(ctx, userID, secretID)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &protov1.GetSecretResponse{
		Secret: modelToProto(secret),
	}, nil
}

// ListSecrets returns metadata summaries for all secrets.
func (s *SecretServer) ListSecrets(ctx context.Context, _ *protov1.ListSecretsRequest) (*protov1.ListSecretsResponse, error) {
	userID, err := parseUserID(ctx)
	if err != nil {
		return nil, err
	}

	summaries, err := s.secrets.List(ctx, userID)
	if err != nil {
		return nil, toGRPCError(err)
	}

	out := make([]*protov1.SecretSummary, len(summaries))
	for i, sm := range summaries {
		out[i] = &protov1.SecretSummary{
			Id:        sm.ID.String(),
			Type:      modelToProtoType(sm.Type),
			Comment:   sm.Comment,
			Version:   sm.Version,
			UpdatedAt: sm.UpdatedAt.Unix(),
		}
	}

	return &protov1.ListSecretsResponse{Secrets: out}, nil
}

// UpdateSecret replaces encrypted data with optimistic concurrency.
func (s *SecretServer) UpdateSecret(ctx context.Context, req *protov1.UpdateSecretRequest) (*protov1.UpdateSecretResponse, error) {
	userID, err := parseUserID(ctx)
	if err != nil {
		return nil, err
	}

	secretID, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid secret id")
	}

	newVersion, err := s.secrets.Update(ctx, userID, secretID,
		req.GetExpectedVersion(),
		req.GetEncryptedData(),
		req.GetEncryptedMetadata(),
		req.GetComment(),
	)
	if err != nil {
		if errors.Is(err, model.ErrConflict) {
			// Version mismatch (optimistic concurrency). Aborted is the
			// canonical gRPC code for a precondition failure; AlreadyExists
			// (used by toGRPCError for ErrConflict) means "entity already
			// exists" and is semantically wrong here.
			return nil, status.Error(codes.Aborted, "version conflict")
		}
		return nil, toGRPCError(err)
	}

	return &protov1.UpdateSecretResponse{Version: newVersion}, nil
}

// DeleteSecret performs a soft delete.
func (s *SecretServer) DeleteSecret(ctx context.Context, req *protov1.DeleteSecretRequest) (*protov1.DeleteSecretResponse, error) {
	userID, err := parseUserID(ctx)
	if err != nil {
		return nil, err
	}

	secretID, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid secret id")
	}

	if err := s.secrets.Delete(ctx, userID, secretID); err != nil {
		return nil, toGRPCError(err)
	}

	return &protov1.DeleteSecretResponse{}, nil
}

// Helpers.

func parseUserID(ctx context.Context) (uuid.UUID, error) {
	idStr, ok := UserIDFromContext(ctx)
	if !ok {
		return uuid.Nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		return uuid.Nil, status.Error(codes.Unauthenticated, "invalid user id in context")
	}
	return id, nil
}

func protoToModelType(t protov1.SecretType) model.SecretType {
	return model.SecretType(t)
}

func modelToProtoType(t model.SecretType) protov1.SecretType {
	return protov1.SecretType(t)
}

func modelToProto(s *model.Secret) *protov1.Secret {
	secret := &protov1.Secret{
		Id:                s.ID.String(),
		Type:              modelToProtoType(s.Type),
		EncryptedData:     s.EncryptedData,
		EncryptedMetadata: s.EncryptedMetadata,
		Comment:           s.Comment,
		Version:           s.Version,
		CreatedAt:         s.CreatedAt.Unix(),
		UpdatedAt:         s.UpdatedAt.Unix(),
	}
	return secret
}
