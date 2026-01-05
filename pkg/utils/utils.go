package utils

import (
	"regexp"
	"strings"

	rand2 "golang.org/x/exp/rand"
)

func RandomString(n uint) string {
	var letterRunes = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
	b := make([]byte, n)
	for i := range b {
		b[i] = letterRunes[rand2.Intn(len(letterRunes))]
	}
	return string(b)
}
func FilterAlphaNumeric(inputString string) string {
	// Регулярное выражение для поиска всех символов, кроме цифр и латиницы
	reg := regexp.MustCompile(`[^a-zA-Z0-9_]`)

	// Применение регулярного выражения для удаления ненужных символов
	filteredString := reg.ReplaceAllString(inputString, "")

	// Приведение строки к нижнему регистру для унификации
	filteredString = strings.ToLower(filteredString)

	return filteredString
}
