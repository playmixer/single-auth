package authtools

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// VerifyJWT - Проверяет JWT.
func VerifyJWT(secretKey string, signedData string) (map[string]string, bool) {
	data := make(map[string]string)
	token, err := jwt.Parse(signedData, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unknown signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil {
		return data, false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		for k, v := range claims {
			if val, ok := v.(string); ok {
				data[k] = val
			}
		}
		return data, token.Valid
	}

	return data, false
}

// CreateJWT - Создает JWT ключ и записывает в него ID пользователя.
func CreateJWT(secretKey string, data map[string]string) (string, error) {
	var payload jwt.MapClaims = make(jwt.MapClaims)
	for k, v := range data {
		payload[k] = v
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", fmt.Errorf("failed signe token: %w", err)
	}

	return tokenString, nil
}
