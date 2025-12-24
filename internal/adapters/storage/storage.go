package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/playmixer/single-auth/internal/adapters/storage/database"
	"github.com/playmixer/single-auth/internal/adapters/storage/filestore"
	"github.com/playmixer/single-auth/internal/adapters/storage/models"
	"github.com/playmixer/single-auth/internal/adapters/storage/redisdb"
	"github.com/playmixer/single-auth/internal/adapters/storage/types"
)

type Config struct {
	TypeStorage string `env:"AUTH_STORAGE" envDefault:"file"`
	Database    database.Config
	File        filestore.Config
}

type Storage interface {
	GetUser(ctx context.Context, username string) (*models.User, error)
	CreateUser(ctx context.Context, username string, email string, passwordHash string) (*models.User, error)
	GetUserByID(ctx context.Context, userID uint) (*models.User, error)

	Close() error
}

func New(cfg Config) (Storage, error) {
	if cfg.TypeStorage == "file" {
		store, err := filestore.New()
		if err != nil {
			return nil, fmt.Errorf("failed init file storage: %w", err)
		}
		return store, nil
	}

	if cfg.TypeStorage == "database" {
		store, err := database.New(cfg.Database.DSN)
		if err != nil {
			return nil, fmt.Errorf("failed init databse storage: %w", err)
		}
		return store, nil
	}

	return nil, fmt.Errorf("filed found type storage")
}

type ConfigCache struct {
	Redis redisdb.Config
}

type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	GetH(ctx context.Context, key string, obj types.ObjInterface) (err error)
	SetH(ctx context.Context, key string, value types.ObjInterface, ttl time.Duration) error
}

func NewCache(cfg ConfigCache) (Cache, error) {
	return redisdb.New(cfg.Redis), nil
}
