package filestore

import (
	"auth/internal/adapters/apperror"
	"auth/internal/adapters/types"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

type userData struct {
	ID           uint
	Username     string
	Email        string
	PasswordHash string
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

func (s *Filestore) CreateUser(ctx context.Context, username string, passwordHash string) (*types.User, error) {
	_, err := s.GetUser(ctx, username)
	if err == nil {
		return nil, fmt.Errorf("user is exited")
	}
	user := userData{
		ID:           uint(time.Now().Unix()),
		Username:     username,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	s.dataUser = append(s.dataUser, user)

	return &types.User{
		ID:           user.ID,
		Username:     user.Username,
		PasswordHash: user.PasswordHash,
		Email:        user.Email,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	}, nil
}

func (s *Filestore) GetUser(ctx context.Context, username string) (*types.User, error) {
	for _, user := range s.dataUser {
		if user.Username == username {
			return &types.User{
				ID:           user.ID,
				Username:     user.Username,
				PasswordHash: user.PasswordHash,
				Email:        user.Email,
				CreatedAt:    user.CreatedAt,
				UpdatedAt:    user.UpdatedAt,
			}, nil
		}
	}

	return nil, apperror.ErrNotFoundData
}

func (s *Filestore) GetUserByID(ctx context.Context, userID uint) (*types.User, error) {
	for _, user := range s.dataUser {
		if user.ID == userID {
			return &types.User{
				ID:           user.ID,
				Username:     user.Username,
				PasswordHash: user.PasswordHash,
				Email:        user.Email,
				CreatedAt:    user.CreatedAt,
				UpdatedAt:    user.UpdatedAt,
			}, nil
		}
	}

	return nil, apperror.ErrNotFoundData
}
