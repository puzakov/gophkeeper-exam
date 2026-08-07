// Package service implements business logic for authentication, secrets and sync.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/puzakov/gophkeeper-exam/internal/model"
	"github.com/puzakov/gophkeeper-exam/internal/storage"
)

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 30 * 24 * time.Hour // 30 days
	bcryptCost      = 12
)

// AuthService handles user registration, login, and token management.
type AuthService struct {
	users         storage.UserRepository
	refreshTokens storage.RefreshTokenRepository
	jwtSecret     []byte
}

// NewAuthService creates a new AuthService.
func NewAuthService(users storage.UserRepository, tokens storage.RefreshTokenRepository, jwtSecret string) *AuthService {
	return &AuthService{
		users:         users,
		refreshTokens: tokens,
		jwtSecret:     []byte(jwtSecret),
	}
}

// Register creates a new user account. Returns the created user and token pair.
func (s *AuthService) Register(ctx context.Context, login, password string, kekSalt, wrappedDEK []byte, kekParams string) (*model.User, string, string, error) {
	if err := validateLogin(login); err != nil {
		return nil, "", "", err
	}
	if err := validatePassword(password); err != nil {
		return nil, "", "", err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return nil, "", "", fmt.Errorf("hash password: %w", err)
	}

	user := &model.User{
		Login:        login,
		PasswordHash: string(hash),
		KEKSalt:      kekSalt,
		WrappedDEK:   wrappedDEK,
		KEKParams:    kekParams,
	}

	if err := s.users.Create(ctx, user); err != nil {
		return nil, "", "", err
	}

	accessToken, refreshToken, err := s.generateTokens(user.ID)
	if err != nil {
		return nil, "", "", fmt.Errorf("generate tokens: %w", err)
	}

	return user, accessToken, refreshToken, nil
}

// Login authenticates a user and returns a new token pair.
func (s *AuthService) Login(ctx context.Context, login, password string) (*model.User, string, string, error) {
	user, err := s.users.GetByLogin(ctx, login)
	if err != nil {
		return nil, "", "", err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, "", "", model.ErrUnauthorized
	}

	accessToken, refreshToken, err := s.generateTokens(user.ID)
	if err != nil {
		return nil, "", "", fmt.Errorf("generate tokens: %w", err)
	}

	return user, accessToken, refreshToken, nil
}

// RefreshToken validates a refresh token, revokes it, and issues a new pair.
func (s *AuthService) RefreshToken(ctx context.Context, tokenStr string) (uuid.UUID, string, string, error) {
	tokenHash := hashToken(tokenStr)

	stored, err := s.refreshTokens.GetByHash(ctx, tokenHash)
	if err != nil {
		return uuid.Nil, "", "", model.ErrUnauthorized
	}

	if stored.RevokedAt != nil {
		return uuid.Nil, "", "", model.ErrRevoked
	}
	if time.Now().After(stored.ExpiresAt) {
		return uuid.Nil, "", "", model.ErrExpired
	}

	// Rotate: revoke old, issue new.
	if err := s.refreshTokens.Revoke(ctx, tokenHash); err != nil {
		return uuid.Nil, "", "", fmt.Errorf("revoke old token: %w", err)
	}

	accessToken, newRefreshToken, err := s.issueTokenPair(ctx, stored.UserID)
	if err != nil {
		return uuid.Nil, "", "", err
	}

	return stored.UserID, accessToken, newRefreshToken, nil
}

// Logout revokes the given refresh token.
func (s *AuthService) Logout(ctx context.Context, tokenStr string) error {
	tokenHash := hashToken(tokenStr)
	return s.refreshTokens.Revoke(ctx, tokenHash)
}

// ValidateAccessToken parses and validates a JWT access token, returning the user ID.
func (s *AuthService) ValidateAccessToken(tokenStr string) (uuid.UUID, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return uuid.Nil, model.ErrUnauthorized
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return uuid.Nil, model.ErrUnauthorized
	}

	sub, err := claims.GetSubject()
	if err != nil {
		return uuid.Nil, model.ErrUnauthorized
	}

	userID, err := uuid.Parse(sub)
	if err != nil {
		return uuid.Nil, model.ErrUnauthorized
	}

	return userID, nil
}

// generateTokens creates both access and refresh tokens for a user.
func (s *AuthService) generateTokens(userID uuid.UUID) (string, string, error) {
	return s.issueTokenPair(context.Background(), userID)
}

func (s *AuthService) issueTokenPair(ctx context.Context, userID uuid.UUID) (string, string, error) {
	accessToken, err := s.issueAccessToken(userID)
	if err != nil {
		return "", "", err
	}
	refreshToken, err := s.issueRefreshToken(ctx, userID)
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

func (s *AuthService) issueAccessToken(userID uuid.UUID) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": userID.String(),
		"iat": now.Unix(),
		"exp": now.Add(accessTokenTTL).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func (s *AuthService) issueRefreshToken(ctx context.Context, userID uuid.UUID) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	tokenStr := hex.EncodeToString(raw)
	tokenHash := hashToken(tokenStr)

	rt := &model.RefreshToken{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(refreshTokenTTL),
	}

	if err := s.refreshTokens.Create(ctx, rt); err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}

	return tokenStr, nil
}

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func validateLogin(login string) error {
	if len(login) < 3 || len(login) > 255 {
		return fmt.Errorf("%w: login must be 3–255 characters", model.ErrInvalid)
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("%w: password must be at least 8 characters", model.ErrInvalid)
	}
	return nil
}
