package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
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
	if err := s.db.AutoMigrate(
		&models.User{},
		&models.Application{},
	); err != nil {
		return fmt.Errorf("failed migrations: %w", err)
	}
	return nil
}

func (s *Storage) CreateUser(ctx context.Context, login, email, passwordHash string) (*models.User, error) {
	login = strings.ToLower(login)
	email = strings.ToLower(email)
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
	login = strings.ToLower(login)
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

func (s *Storage) UpdUser(ctx context.Context, user *models.User) error {
	err := s.db.WithContext(ctx).Where("id = ?", user.ID).Updates(user).Error
	if err != nil {
		return fmt.Errorf("failed update user: %w", err)
	}

	return nil
}

func (s *Storage) FindUsersByLogin(ctx context.Context, login string) ([]models.User, error) {
	login = strings.ToLower(login)
	users := []models.User{}

	err := s.db.WithContext(ctx).Where("login like ?", "%"+login+"%").Find(&users).Error
	if err != nil && !errors.Is(gorm.ErrRecordNotFound, err) {
		return users, fmt.Errorf("failes find users: %w", err)
	}

	return users, nil
}

func (s *Storage) RemoveUser(ctx context.Context, userID uint) error {
	return s.db.WithContext(ctx).Where("id = ?", userID).Delete(&models.User{}).Error
}

func (s *Storage) CreateApplication(ctx context.Context, title, link string) (*models.Application, error) {
	app := &models.Application{
		Title:    title,
		AuthLink: link,
	}

	err := s.db.WithContext(ctx).Create(app).Error
	if err != nil {
		return nil, fmt.Errorf("failed create application: %w", err)
	}

	return app, nil
}

func (s *Storage) GetApplication(ctx context.Context, appID string) (*models.Application, error) {
	app := &models.Application{}
	err := s.db.WithContext(ctx).Where("id = ?", appID).First(app).Error
	if err != nil {
		return nil, errors.Join(err, apperror.ErrNotFoundData)
	}

	return app, nil
}

func (s *Storage) UpdateApplication(ctx context.Context, app *models.Application) error {
	err := s.db.WithContext(ctx).Where("id = ?", app.ID).Updates(app).Error
	if err != nil {
		return fmt.Errorf("failed update applicatioh: %w", err)
	}

	return nil
}

func (s *Storage) RemoveApplication(ctx context.Context, appID string) error {
	err := s.db.WithContext(ctx).Where("id = ?", appID).Delete(&models.Application{}).Error
	if err != nil {
		return fmt.Errorf("failed remove application: %w", err)
	}

	return nil
}

func (s *Storage) GetApplicationByTitle(ctx context.Context, title string) (*models.Application, error) {
	app := &models.Application{}
	err := s.db.WithContext(ctx).Where("title = ?", title).First(app).Error
	if err != nil {
		return nil, errors.Join(err, apperror.ErrNotFoundData)
	}

	return app, nil
}

func (s *Storage) FindApplicationByTitle(ctx context.Context, title string) ([]models.Application, error) {
	apps := []models.Application{}
	err := s.db.WithContext(ctx).Where("title like ?", "%"+title+"%").Find(&apps).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, errors.Join(err, apperror.ErrNotFoundData)
	}

	return apps, nil
}
