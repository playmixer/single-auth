package rest

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/playmixer/single-auth/internal/adapters/storage/models"
	"github.com/playmixer/single-auth/pkg/utils"
	"go.uber.org/zap"
)

func (s *Server) handlerLogin(c *gin.Context) {
	var err error
	var userID string
	isAuth := false
	var user *models.User
	userID, err = s.checkAuth(c)
	var userIDInt int
	if err == nil {
		userIDInt, err = strconv.Atoi(userID)
	}
	if err == nil {
		user, err = s.auth.GetUserByID(c.Request.Context(), uint(userIDInt))
	}
	if err == nil {
		isAuth = true
	}

	c.HTML(http.StatusOK, "login.html", gin.H{
		"status": "ok",
		"isAuth": isAuth,
		"user":   user,
	})
}

func (s *Server) handlerAPILogin(c *gin.Context) {
	var err error

	var data tUser
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	user := &models.User{}
	key := "user:" + data.Username
	if err = s.cache.GetH(c.Request.Context(), key, user); err != nil {
		if user, err = s.auth.GetUser(c.Request.Context(), data.Username); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user data"})
			return
		}

		err = s.cache.SetH(c.Request.Context(), key, user, time.Second*30)
		if err != nil {
			s.log.Error("failed save to cache", zap.String("key", key), zap.Error(err))
		}
	}
	s.log.Debug("get user", zap.Any("user", *user))

	// Сравниваем введённый пароль с хэшем
	if ok := utils.CheckPasswordHash(user.PasswordHash, data.Password); !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "incorrect username or password"})
		return
	}

	token, err := s.auth.CreateJWT(map[string]string{
		"userID": strconv.Itoa(int(user.ID)),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "failed create token",
			"message": err.Error(),
		})
		return
	}
	for _, domain := range s.cookieDomain {
		s.log.Debug("save cookie", zap.String("host", domain), zap.String("token", token))
		c.SetCookie(CookieNameToken, token, 0, "/", domain, s.cookieSecure, true)
	}
	// Если всё прошло успешно
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		// "token":   token,
	})
}

func (s *Server) handlerLogut(c *gin.Context) {
	for _, domain := range s.cookieDomain {
		c.SetCookie(CookieNameToken, "", 0, "/", domain, s.cookieSecure, true)
	}

	c.Redirect(http.StatusTemporaryRedirect, "/auth/login")
}

func (s *Server) handlerAPIUserAuthInfo(c *gin.Context) {
	var err error
	var userID string
	var user *models.User
	userID, err = s.checkAuth(c)
	var userIDInt int
	if err == nil {
		userIDInt, err = strconv.Atoi(userID)
	}
	if err == nil {
		user, err = s.auth.GetUserByID(c.Request.Context(), uint(userIDInt))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized",
			})
			return
		}
	}

	cookie, _ := c.Request.Cookie(CookieNameToken)
	params, appLink, err := s.auth.GetPayloadUser(c.Query("appID"), map[string]string{
		"username": user.Login,
		"email":    user.Email,
		"token":    cookie.Value,
	})
	if err != nil {
		s.log.Error("failed generate app params", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "failed generate app params",
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"params":  params,
		"appLink": appLink,
	})
}
