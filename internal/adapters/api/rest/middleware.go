package rest

import (
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
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
		var userCookie *http.Cookie
		var data = make(map[string]string)
		userCookie, err := c.Request.Cookie(CookieNameToken)
		if err == nil {
			data, ok = s.auth.VerifyJWT(userCookie.Value)
		}
		if err != nil || !ok {
			data["updTime"] = strconv.Itoa(int(time.Now().Unix()))
			signedCookie, err := s.auth.CreateJWT(data)
			if err != nil {
				s.log.Info("failed sign cookies", zap.Error(err))
				c.Writer.WriteHeader(http.StatusInternalServerError)
				c.Abort()
				return
			}
			userCookie = &http.Cookie{
				Name:  CookieNameToken,
				Value: signedCookie,
				Path:  "/",
			}
			c.Request.AddCookie(userCookie)
		}

		http.SetCookie(c.Writer, userCookie)
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
