package config

import (
	"fmt"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
	"github.com/playmixer/single-auth/internal/adapters/api/rest"
	"github.com/playmixer/single-auth/internal/adapters/storage"
	"github.com/playmixer/single-auth/internal/adapters/storage/database"
	"github.com/playmixer/single-auth/internal/adapters/storage/filestore"
)

// Config конфигурация сервиса.
type Config struct {
	API rest.Config
	// Store    storage.Config
	LogLevel  string `env:"LOG_LEVEL"`
	SecretKey string `env:"AUTH_SECRET_KEY"`
	Store     storage.Config
	Cache     storage.ConfigCache
}

// Init инициализирует конфигурацию сервиса.
func Init() (*Config, error) {
	cfg := Config{
		API: rest.Config{},
		Store: storage.Config{
			File:     filestore.Config{},
			Database: database.Config{},
		},
		Cache: storage.ConfigCache{},
	}

	_ = godotenv.Load(".env")

	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("error parse config %w", err)
	}

	return &cfg, nil
}
