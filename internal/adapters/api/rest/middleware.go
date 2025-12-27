package rest

import (
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/playmixer/single-auth/internal/adapters/storage/models"
	"go.uber.org/zap"
)

// Logger middleware логирования.
func (s *Server) middlewareLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		s.log.Info(
			"Request information",
			zap.String("uri", c.Request.RequestURI),
			zap.Duration("duration", time.Since(start)),
			zap.String("method", c.Request.Method),
			zap.Int("status", c.Writer.Status()),
			zap.Int("size", c.Writer.Size()),
		)
	}
}

// CheckCookies middleware проверка куки файлов.
func (s *Server) middlewareCheckCookies() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ok bool
		var data map[string]string
		var userCookie *http.Cookie
		userCookie, err := c.Request.Cookie(CookieJWT)
		if err == nil {
			data, ok = s.auth.VerifyJWT(userCookie.Value)
		}
		if err != nil || !ok {
			s.log.Debug("failed sign cookies", zap.Error(err))
			c.Writer.WriteHeader(http.StatusUnauthorized)
			c.Abort()
			return
		}

		// Проверяем наличия даты когда токин истечет
		expiredDateS, ok := data["expiredUnix"]
		if !ok {
			s.log.Debug("not found param expired", zap.Error(err))
			c.Abort()
			s.resetCookie(c)
			c.Redirect(http.StatusMovedPermanently, "/auth/login")
			return
		}
		expiredDate, err := strconv.ParseInt(expiredDateS, 10, 64)
		if err != nil {
			s.log.Debug("expired not valid", zap.Error(err))
			c.Abort()
			s.resetCookie(c)
			c.Redirect(http.StatusMovedPermanently, "/auth/login")
			return
		}

		// если access токен просрочен то пытаемся перевыпустить
		currentTime := time.Now().Unix()
		s.log.Debug("token time", zap.Int64("current", currentTime), zap.Int64("expired", expiredDate))
		if currentTime > expiredDate {
			err = func(c *gin.Context) error {
				refreshCookie, err := c.Request.Cookie(CookieRefreshToken)
				if err != nil {
					return fmt.Errorf("not found refresh token, %w", err)
				}
				userIDs, ok := data["userID"]
				if !ok {
					return fmt.Errorf("not found param userID, %w", err)
				}
				userID, err := strconv.Atoi(userIDs)
				if err != nil {
					return fmt.Errorf("userID not valid, %w", err)
				}
				user := &models.User{}
				if user, err = s.auth.GetUserByID(c.Request.Context(), uint(userID)); err != nil {
					return fmt.Errorf("user not found, %w", err)
				}
				token, err := s.auth.CreateJWT(map[string]string{
					"userID":      strconv.Itoa(int(user.ID)),
					"isAdmin":     strconv.FormatBool(user.IsAdmin),
					"expiredUnix": strconv.FormatInt(time.Now().Unix()+int64(s.jwtAccessTokenTTL), 10),
				})
				if err != nil {
					return fmt.Errorf("failed create JWT, %w", err)
				}
				refresh, err := s.auth.UpdRefreshToken(c.Request.Context(), refreshCookie.Value)
				if err != nil {
					return fmt.Errorf("failed update refresh token, %w", err)
				}
				for _, domain := range s.cookieDomain {
					s.log.Debug("save cookie", zap.String("host", domain), zap.String("token", token), zap.String("refresh", refresh))
					c.SetCookie(CookieJWT, token, s.cookieLifeTime, "/", domain, s.cookieSecure, true)
					c.SetCookie(CookieRefreshToken, refresh, s.cookieLifeTime, "/", domain, s.cookieSecure, true)
				}
				return nil
			}(c)
			if err != nil {
				s.log.Debug("failed update token", zap.Error(err))
				c.Writer.WriteHeader(http.StatusUnauthorized)
				c.Abort()
				s.resetCookie(c)
				c.Redirect(http.StatusMovedPermanently, "/auth/login")
				return
			}

		}

		c.Next()
	}
}

func (s *Server) middlewareIsAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ok bool
		var data = make(map[string]string)

		userCookie, err := c.Request.Cookie(CookieJWT)
		if err == nil {
			data, ok = s.auth.VerifyJWT(userCookie.Value)
		}
		if !ok {
			c.Writer.WriteHeader(http.StatusForbidden)
			c.Abort()
			return
		}

		if sIsAdmin, ok := data["isAdmin"]; !ok {
			c.Writer.WriteHeader(http.StatusForbidden)
			c.Abort()
			return
		} else {
			isAdmin, err := strconv.ParseBool(sIsAdmin)
			if err != nil {
				c.Writer.WriteHeader(http.StatusForbidden)
				c.Abort()
				return
			}
			if !isAdmin {
				c.Writer.WriteHeader(http.StatusForbidden)
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// Auth middleware проверка аутентификации пользователя.
func (s *Server) Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, err := s.checkAuth(c)
		if err != nil {
			c.Writer.WriteHeader(http.StatusUnauthorized)
			c.Abort()
		}

		c.Next()
	}
}

// TrustedSubnet middleware проверка сети пользователя как доверенную.
func (s *Server) TrustedSubnet() gin.HandlerFunc {
	return func(c *gin.Context) {
		access := true
		network, err := netip.ParsePrefix(s.trustedSubnet)
		if err != nil {
			s.log.Debug("trusted subnet is not valid", zap.Error(err), zap.String("subnet", s.trustedSubnet))
			access = false
		}
		ipStr := c.Request.Header.Get("X-Real-IP")
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			s.log.Debug("IP address is not valid", zap.Error(err), zap.String("ip", ipStr))
			access = false
		}
		if ok := network.Contains(ip); !ok {
			access = false
		}

		if !access {
			c.Writer.WriteHeader(http.StatusForbidden)
			c.Abort()
		}
		c.Next()
	}
}
