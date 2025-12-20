package rest

import "strings"

type stringList string

// Config конфигурация REST сервиса.
type Config struct {
	Addr         string     `env:"SERVER_ADDRESS"`
	BaseURL      string     `env:"SERVER_BASEURL"`
	CookieDomain stringList `env:"COOKIE_DOMAIN" envDefault:"localhost"`
	CookieSecure bool       `env:"COOKIE_SECURE" envDefault:"false"`
}

func (s stringList) List() []string {
	split := strings.Split(string(s), ";")
	return split
}
