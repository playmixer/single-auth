package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
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
		&models.Session{},
		&models.Role{},
	); err != nil {
		return fmt.Errorf("failed migrations: %w", err)
	}
	return nil
}

func (s *Storage) CreateUser(ctx context.Context, login, email, passwordHash string, admin bool) (*models.User, error) {
	login = strings.ToLower(login)
	email = strings.ToLower(email)
	user := &models.User{
		Login:        login,
		PasswordHash: passwordHash,
		Email:        email,
		Model: gorm.Model{
			CreatedAt: time.Now(),
		},
		IsAdmin: admin,
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
	err := s.db.WithContext(ctx).Where("login = ?", login).Preload("Roles").First(user).Error
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
	err := s.db.WithContext(ctx).Where("id = ?", userID).Preload("Roles").First(user).Error
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
	err := s.db.WithContext(ctx).Where("id = ?", user.ID).Save(user).Error
	if err != nil {
		return fmt.Errorf("failed update user: %w", err)
	}

	return nil
}

func (s *Storage) FindUsersByLogin(ctx context.Context, login string) ([]models.User, error) {
	login = strings.ToLower(login)
	users := []models.User{}

	err := s.db.WithContext(ctx).Where("login like ?", "%"+login+"%").Preload("Roles").Find(&users).Error
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
	err := s.db.WithContext(ctx).Where("id = ?", appID).Preload("Roles").First(app).Error
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
	err := s.db.WithContext(ctx).Where("title like ?", "%"+title+"%").Preload("Roles").Find(&apps).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, errors.Join(err, apperror.ErrNotFoundData)
	}

	return apps, nil
}

func (s *Storage) CreateRefreshToken(ctx context.Context, userID uint, token string, expiredDate time.Time) error {
	session := &models.Session{
		UserID:      userID,
		Token:       token,
		ExpiredDate: expiredDate,
	}

	err := s.db.WithContext(ctx).Create(session).Error
	if err != nil {
		return fmt.Errorf("failed create refresh token: %w", err)
	}

	return nil
}

func (s *Storage) RemoveRefreshToken(ctx context.Context, refresh string) error {
	err := s.db.WithContext(ctx).Where("token =?", refresh).Delete(&models.Session{}).Error
	if err != nil {
		return fmt.Errorf("failed remove refresh token: %w", err)
	}

	return nil
}

func (s *Storage) getSessionByToken(ctx context.Context, refresh string) (*models.Session, error) {
	session := &models.Session{}
	err := s.db.WithContext(ctx).Where("token = ?", refresh).First(session).Error
	if err != nil {
		return nil, fmt.Errorf("failed getting token: %w", err)
	}

	return session, nil
}

func (s *Storage) UpdRefreshToken(ctx context.Context, oldRefresh, newRefresh string) error {
	session, err := s.getSessionByToken(ctx, oldRefresh)
	if err != nil {
		return fmt.Errorf("failed getting session by token: %w", err)
	}
	session.Token = newRefresh
	err = s.db.WithContext(ctx).Where("token = ?", oldRefresh).Updates(session).Error
	if err != nil {
		return fmt.Errorf("failed update refresh token: %w", err)
	}

	return nil
}

func (s *Storage) CreateRole(ctx context.Context, appID, name, description string) (*models.Role, error) {
	role := &models.Role{
		Name:          name,
		Description:   description,
		ApplicationID: uuid.MustParse(appID),
	}
	err := s.db.WithContext(ctx).Create(role).Error
	if err != nil {
		return nil, fmt.Errorf("failed create role: %w", err)
	}

	return role, nil
}

func (s *Storage) UpdRole(ctx context.Context, role *models.Role) error {
	err := s.db.WithContext(ctx).Updates(role).Error
	if err != nil {
		return fmt.Errorf("failed update role: %w", err)
	}
	return nil
}

func (s *Storage) GetRole(ctx context.Context, roleID uint) (*models.Role, error) {
	role := &models.Role{}
	err := s.db.WithContext(ctx).Where("id = ?", roleID).First(role).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.Join(err, apperror.ErrNotFoundData)
		}
		return nil, fmt.Errorf("failed getting role: %w", err)
	}

	return role, nil
}

func (s *Storage) UpdUserRoles(ctx context.Context, user *models.User, roles []models.Role) error {
	err := s.db.WithContext(ctx).Model(user).Association("Roles").Replace(roles)
	if err != nil {
		return fmt.Errorf("failed update user roles: %w", err)
	}

	return nil
}
