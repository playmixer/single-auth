package storage

import (
	"auth/internal/adapters/storage/filestore"
	"auth/internal/adapters/types"
	"context"
)

type Storage interface {
	GetUser(ctx context.Context, username string) (*types.User, error)
	CreateUser(ctx context.Context, username string, passwordHash string) (*types.User, error)
	GetUserByID(ctx context.Context, userID uint) (*types.User, error)

	Close() error
}

func New() (Storage, error) {
	return filestore.New()
}
