package auth

import (
	"auth/internal/adapters/apperror"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

var (
	errNotFoundFile = errors.New("file not found")
)

const (
	fileSetting = "./app.auth.setting.json"
)

type AppData struct {
	AppID     string `json:"appID"`
	AuthLink  string `json:"authLink"`
	SecretKey string `json:"secretKey"`
}

type ApplicationAuth struct {
	data map[string]AppData
}

func InitApplicationAuthSettings() *ApplicationAuth {
	a := &ApplicationAuth{
		data: make(map[string]AppData),
	}
	if err := a.load(); err != nil {
		fmt.Println(err)
	}
	return a
}

func (a *ApplicationAuth) load() error {
	// Проверяем существование файла
	_, err := os.Stat(fileSetting)
	if os.IsNotExist(err) {
		return errNotFoundFile
	}

	// Читаем содержимое файла
	data, err := os.ReadFile(fileSetting)
	if err != nil {
		return fmt.Errorf("error reading file: %s", err.Error())
	}

	appsData := []AppData{}
	// Парсим данные в структуру
	err = json.Unmarshal(data, &appsData)
	if err != nil {
		return fmt.Errorf("error parsing file: %s", err.Error())
	}

	for _, app := range appsData {
		a.data[app.AppID] = app
	}

	return nil
}

func (a *ApplicationAuth) GetAppByID(appID string) (AppData, error) {
	if v, ok := a.data[appID]; ok {
		return v, nil
	}

	return AppData{}, apperror.ErrNotFoundData
}
