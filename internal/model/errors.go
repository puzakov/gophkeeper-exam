package model

import "errors"

// Sentinel errors used across the application.
var (
	ErrNotFound     = errors.New("not found")
	ErrConflict     = errors.New("conflict")
	ErrUnauthorized = errors.New("unauthorized")
	ErrInvalid      = errors.New("invalid argument")
	ErrExpired      = errors.New("token expired")
	ErrRevoked      = errors.New("token revoked")
)
