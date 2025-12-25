package filestore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/playmixer/single-auth/internal/adapters/apperror"
	"github.com/playmixer/single-auth/internal/adapters/storage/models"
	"gorm.io/gorm"
)

type Config struct{}

type userData struct {
	ID           uint
	Login        string
	Email        string
	PasswordHash string
	IsAdmin      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

const (
	userfile = "./data/userdata.json"
)

var (
	errNotFoundFile = errors.New("file not found")
)

type Filestore struct {
	dataUser []userData
}

func New() (*Filestore, error) {
	s := &Filestore{
		dataUser: make([]userData, 0),
	}

	err := s.loadUsers()
	if err != nil && !errors.Is(err, errNotFoundFile) {
		return nil, err
	}

	return s, nil
}

func (s *Filestore) Close() error {
	var errs error
	if err := s.saveUsers(); err != nil {
		errs = errors.Join(err, fmt.Errorf("failed save user store: %w", err))
	}
	return errs
}

func (s *Filestore) saveUsers() error {
	// Создаём файл для записи
	file, err := os.Create(userfile)
	if err != nil {
		return fmt.Errorf("error creating file: %s", err.Error())
	}
	defer file.Close()

	// Преобразуем структуру в JSON и записываем в файл
	data, err := json.Marshal(s.dataUser)
	if err != nil {
		return fmt.Errorf("error marshalling struct to JSON: %s", err.Error())
	}

	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("error writing to file: %s", err.Error())
	}

	return nil
}

func (s *Filestore) loadUsers() error {
	// Проверяем существование файла
	_, err := os.Stat(userfile)
	if os.IsNotExist(err) {
		return errNotFoundFile
	}

	// Читаем содержимое файла
	data, err := os.ReadFile(userfile)
	if err != nil {
		return fmt.Errorf("error reading file: %s", err.Error())
	}

	// Парсим данные в структуру
	err = json.Unmarshal(data, &s.dataUser)
	if err != nil {
		return fmt.Errorf("error parsing file: %s", err.Error())
	}

	return nil
}

func (s *Filestore) CreateUser(ctx context.Context, login, email string, passwordHash string) (*models.User, error) {
	_, err := s.GetUser(ctx, login)
	if err == nil {
		return nil, fmt.Errorf("user is exited")
	}
	user := userData{
		ID:           uint(time.Now().Unix()),
		Login:        login,
		Email:        email,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	s.dataUser = append(s.dataUser, user)

	return &models.User{
		Login:        user.Login,
		PasswordHash: user.PasswordHash,
		Email:        user.Email,
		Model: gorm.Model{
			ID:        user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		},
	}, nil
}

func (s *Filestore) GetUser(ctx context.Context, login string) (*models.User, error) {
	for _, user := range s.dataUser {
		if user.Login == login {
			return &models.User{
				Login:        user.Login,
				PasswordHash: user.PasswordHash,
				Email:        user.Email,
				Model: gorm.Model{
					ID:        user.ID,
					CreatedAt: user.CreatedAt,
					UpdatedAt: user.UpdatedAt,
				},
			}, nil
		}
	}

	return nil, apperror.ErrNotFoundData
}

func (s *Filestore) GetUserByID(ctx context.Context, userID uint) (*models.User, error) {
	for _, user := range s.dataUser {
		if user.ID == userID {
			return &models.User{
				Login:        user.Login,
				PasswordHash: user.PasswordHash,
				Email:        user.Email,
				Model: gorm.Model{
					ID:        user.ID,
					CreatedAt: user.CreatedAt,
					UpdatedAt: user.UpdatedAt,
				},
			}, nil
		}
	}

	return nil, apperror.ErrNotFoundData
}

func (s *Filestore) UpdUser(ctx context.Context, user *models.User) error {
	for i, u := range s.dataUser {
		if u.ID == user.ID {
			s.dataUser[i] = userData{
				ID:           user.ID,
				Login:        user.Login,
				Email:        user.Email,
				PasswordHash: user.PasswordHash,
				CreatedAt:    user.CreatedAt,
				UpdatedAt:    time.Now(),
			}
			return nil
		}
	}

	return apperror.ErrNotFoundData
}

func (s *Filestore) FindUsersByLogin(ctx context.Context, login string) ([]models.User, error) {
	users := []models.User{}

	for _, u := range s.dataUser {
		if strings.Contains(u.Login, login) {
			users = append(users, models.User{
				Model: gorm.Model{
					ID:        u.ID,
					CreatedAt: u.CreatedAt,
					UpdatedAt: u.UpdatedAt,
				},
				Login:        u.Login,
				Email:        u.Email,
				PasswordHash: "",
				IsAdmin:      u.IsAdmin,
			})
		}
	}

	return users, nil
}

func (s *Filestore) RemoveUser(ctx context.Context, userID uint) error {
	for i, u := range s.dataUser {
		if u.ID == userID {
			s.dataUser = append(s.dataUser[:i], s.dataUser[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("user not found by id: %v", userID)
}

func (s *Filestore) CreateApplication(ctx context.Context, title, link string) (*models.Application, error) {
	return nil, errors.New("method not implemented")
}

func (s *Filestore) UpdateApplication(ctx context.Context, app *models.Application) error {
	return errors.New("method not implemented")
}

func (s *Filestore) RemoveApplication(ctx context.Context, appID string) error {
	return errors.New("method not implemented")
}

func (s *Filestore) GetApplication(ctx context.Context, appID string) (*models.Application, error) {
	return nil, errors.New("method not implemented")
}

func (s *Filestore) GetApplicationByTitle(ctx context.Context, title string) (*models.Application, error) {
	return nil, errors.New("method not implemented")
}

func (s *Filestore) FindApplicationByTitle(ctx context.Context, title string) ([]models.Application, error) {
	return nil, errors.New("method not implemented")
}
