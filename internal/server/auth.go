package server

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/puzakov/gophkeeper-exam/internal/model"
	protov1 "github.com/puzakov/gophkeeper-exam/internal/proto/v1"
	"github.com/puzakov/gophkeeper-exam/internal/service"
)

// AuthServer implements the proto AuthService.
type AuthServer struct {
	protov1.UnimplementedAuthServiceServer
	auth *service.AuthService
}

// NewAuthServer creates a new AuthServer.
func NewAuthServer(auth *service.AuthService) *AuthServer {
	return &AuthServer{auth: auth}
}

// Register handles user registration.
func (s *AuthServer) Register(ctx context.Context, req *protov1.RegisterRequest) (*protov1.AuthResponse, error) {
	user, accessToken, refreshToken, err := s.auth.Register(
		ctx,
		req.GetLogin(),
		req.GetPassword(),
		req.GetKekSalt(),
		req.GetWrappedDek(),
		req.GetKekParams(),
	)
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &protov1.AuthResponse{
		UserId:       user.ID.String(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    900, // 15 minutes
	}, nil
}

// Login handles user authentication.
func (s *AuthServer) Login(ctx context.Context, req *protov1.LoginRequest) (*protov1.AuthResponse, error) {
	user, accessToken, refreshToken, err := s.auth.Login(ctx, req.GetLogin(), req.GetPassword())
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &protov1.AuthResponse{
		UserId:       user.ID.String(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    900,
		KekSalt:      user.KEKSalt,
		WrappedDek:   user.WrappedDEK,
		KekParams:    user.KEKParams,
	}, nil
}

// RefreshToken issues a new token pair from a valid refresh token.
func (s *AuthServer) RefreshToken(ctx context.Context, req *protov1.RefreshTokenRequest) (*protov1.AuthResponse, error) {
	userID, accessToken, refreshToken, err := s.auth.RefreshToken(ctx, req.GetRefreshToken())
	if err != nil {
		return nil, toGRPCError(err)
	}

	return &protov1.AuthResponse{
		UserId:       userID.String(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    900,
	}, nil
}

// Logout revokes the given refresh token.
func (s *AuthServer) Logout(ctx context.Context, req *protov1.LogoutRequest) (*protov1.LogoutResponse, error) {
	if err := s.auth.Logout(ctx, req.GetRefreshToken()); err != nil {
		return nil, toGRPCError(err)
	}
	return &protov1.LogoutResponse{}, nil
}

// toGRPCError maps domain errors to gRPC status codes.
func toGRPCError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, model.ErrNotFound):
		return status.Error(codes.NotFound, "not found")
	case errors.Is(err, model.ErrConflict):
		return status.Error(codes.AlreadyExists, "conflict")
	case errors.Is(err, model.ErrUnauthorized):
		return status.Error(codes.Unauthenticated, "unauthorized")
	case errors.Is(err, model.ErrInvalid):
		return status.Error(codes.InvalidArgument, "invalid argument")
	case errors.Is(err, model.ErrExpired):
		return status.Error(codes.Unauthenticated, "token expired")
	case errors.Is(err, model.ErrRevoked):
		return status.Error(codes.Unauthenticated, "token revoked")
	default:
		return status.Error(codes.Internal, "internal error")
	}
}
