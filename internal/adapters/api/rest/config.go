package rest

import "strings"

type stringList string

// Config конфигурация REST сервиса.
type Config struct {
	Addr               string     `env:"SERVER_ADDRESS"`
	BaseURL            string     `env:"SERVER_BASEURL"`
	CookieDomain       stringList `env:"COOKIE_DOMAIN" envDefault:"localhost"`
	CookieSecure       bool       `env:"COOKIE_SECURE" envDefault:"false"`
	CookieLifeTime     int        `env:"COOKIE_LIFETIME" envDefault:"0"`
	JWTAccessTokenTTL  int        `env:"JWT_ACCESS_TOKEN_TTL" envDefault:"86400"`
	JWTRefreshTokenTTL int        `env:"JWT_REFRESH_TOKEN_TTL" envDefault:"604800"`
}

func (s stringList) List() []string {
	split := strings.Split(string(s), ";")
	return split
}
