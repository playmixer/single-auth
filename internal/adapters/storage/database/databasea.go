package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/playmixer/single-auth/internal/adapters/apperror"
	"github.com/playmixer/single-auth/internal/adapters/storage/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Config struct {
	DSN string `env:"DATABASE_ADDRESS"`
}

type Storage struct {
	db *gorm.DB
}

func New(dsn string) (*Storage, error) {
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed open connect: %w", err)
	}
	gormDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn: sqlDB,
	}))
	if err != nil {
		return nil, fmt.Errorf("failed open gorm connect: %w", err)
	}

	db := &Storage{
		db: gormDB,
	}

	if err := db.migration(); err != nil {
		return nil, fmt.Errorf("failed auto migrations: %w", err)
	}

	return db, nil
}

func (s *Storage) migration() error {
	if err := s.db.AutoMigrate(&models.User{}); err != nil {
		return fmt.Errorf("failed migrations: %w", err)
	}
	return nil
}

func (s *Storage) CreateUser(ctx context.Context, login, email, passwordHash string) (*models.User, error) {
	user := &models.User{
		Login:        login,
		PasswordHash: passwordHash,
		Email:        email,
		Model: gorm.Model{
			CreatedAt: time.Now(),
		},
	}

	err := s.db.WithContext(ctx).Create(user).Error
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, fmt.Errorf("login not unique: %w %w", err, apperror.ErrLoginNotUnique)
		}
		return nil, fmt.Errorf("failed create user: %w", err)
	}

	return user, nil
}

func (s *Storage) GetUser(ctx context.Context, login string) (*models.User, error) {
	user := &models.User{}
	err := s.db.WithContext(ctx).Where("login = ?", login).First(user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.Join(apperror.ErrNotFoundData, err)
		}
		return nil, fmt.Errorf("failed find user: %w", err)
	}

	return user, nil
}

func (s *Storage) GetUserByID(ctx context.Context, userID uint) (*models.User, error) {
	user := &models.User{}
	err := s.db.WithContext(ctx).Where("id = ?", userID).First(user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.Join(apperror.ErrNotFoundData, err)
		}
		return nil, fmt.Errorf("failed find user: %w", err)
	}

	return user, nil
}

func (s *Storage) Close() error {
	return nil
}
