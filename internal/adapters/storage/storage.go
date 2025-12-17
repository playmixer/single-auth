package storage

import (
	"context"

	"github.com/playmixer/single-auth/internal/adapters/storage/filestore"
	"github.com/playmixer/single-auth/internal/adapters/types"
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
