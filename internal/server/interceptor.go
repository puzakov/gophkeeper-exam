// Package server implements the gRPC server for GophKeeper.
package server

import (
	"context"
	"strings"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Context key type for storing values in gRPC context.
type ctxKey string

const (
	ctxKeyUserID ctxKey = "user_id"
)

// UserIDFromContext extracts the authenticated user ID from the context.
func UserIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(ctxKeyUserID).(string)
	return id, ok
}

// AuthInterceptor returns a UnaryServerInterceptor that validates JWT access tokens.
// Public methods (Register, Login) are allowed without a token.
func AuthInterceptor(validateToken func(string) (string, error)) grpc.UnaryServerInterceptor {
	publicMethods := map[string]bool{
		"/gophkeeper.v1.AuthService/Register":     true,
		"/gophkeeper.v1.AuthService/Login":        true,
		"/gophkeeper.v1.AuthService/RefreshToken": true,
	}

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		values := md.Get("authorization")
		if len(values) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing authorization header")
		}

		token := strings.TrimPrefix(values[0], "Bearer ")
		if token == values[0] {
			return nil, status.Error(codes.Unauthenticated, "invalid authorization format, expected Bearer <token>")
		}

		userID, err := validateToken(token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
		}

		ctx = context.WithValue(ctx, ctxKeyUserID, userID)
		return handler(ctx, req)
	}
}

// LoggingInterceptor returns a UnaryServerInterceptor that logs each gRPC request
// using the provided logger.
func LoggingInterceptor(log *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()

		resp, err := handler(ctx, req)

		code := status.Code(err)
		log.Info("gRPC request",
			zap.String("method", info.FullMethod),
			zap.String("code", code.String()),
			zap.Duration("duration", time.Since(start)),
		)

		return resp, err
	}
}
