package rest

import (
	"fmt"
	"reflect"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/playmixer/single-auth/internal/adapters/storage/models"
	"go.uber.org/zap"
)

func (s *Server) checkAuth(c *gin.Context) (userID string, err error) {
	var ok bool
	var tknData map[string]string
	cookieUserID, err := c.Request.Cookie(CookieJWT)
	if err == nil {
		tknData, ok = s.auth.VerifyJWT(cookieUserID.Value)
		s.log.Debug("cookie", zap.String("value", cookieUserID.Value), zap.Any("params", tknData))
	}
	if err != nil {
		return "", fmt.Errorf("failed reade user cookie: %w %w", errInvalidAuthCookie, err)
	}
	if !ok {
		return "", fmt.Errorf("unverify usercookie: %w", errInvalidAuthCookie)
	}
	if userID, ok = tknData["userID"]; ok {
		return userID, nil
	}

	return "", fmt.Errorf("failed to read user id from token: %w", errInvalidAuthCookie)
}

func (s *Server) isAuthenticate(c *gin.Context) (isAuth bool, user *models.User, err error) {
	userID, err := s.checkAuth(c)
	var userIDInt int
	if err == nil {
		userIDInt, err = strconv.Atoi(userID)
	}
	if err == nil {
		key := "userid:" + userID
		if err = s.cache.GetH(c.Request.Context(), key, user); err != nil {
			user, err = s.auth.GetUserByID(c.Request.Context(), uint(userIDInt))
			if err != nil {
				isAuth = false
				return
			}

			err = s.cache.SetH(c.Request.Context(), key, user, ttlCacheDefault)
			if err != nil {
				s.log.Error("failed save user to cache", zap.Error(err))
			}
		}
	}
	if err == nil {
		isAuth = true
	}
	return
}

func (s *Server) resetCookie(c *gin.Context) {
	for _, domain := range s.cookieDomain {
		s.log.Debug("clear cookie", zap.String("host", domain))
		c.SetCookie(CookieJWT, "", s.cookieLifeTime, "/", domain, s.cookieSecure, true)
		c.SetCookie(CookieRefreshToken, "", s.cookieLifeTime, "/", domain, s.cookieSecure, true)
	}
}

func empty[T string | int](s T) bool {
	val := reflect.ValueOf(s)

	switch val.Kind() {
	case reflect.String:
		return val.String() == ""
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return val.Int() == 0
	default:
		// Для других типов данных можно добавить дополнительную логику
		return false
	}
}
