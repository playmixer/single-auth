package rest

// Config конфигурация REST сервиса.
type Config struct {
	Addr    string `env:"SERVER_ADDRESS"`
	BaseURL string `env:"SERVER_BASEURL"`
}
