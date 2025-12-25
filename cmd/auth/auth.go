package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/playmixer/single-auth/internal/adapters/api/rest"
	"github.com/playmixer/single-auth/internal/adapters/config"
	"github.com/playmixer/single-auth/internal/adapters/storage"
	"github.com/playmixer/single-auth/internal/core/admin"
	"github.com/playmixer/single-auth/internal/core/auth"
	"github.com/playmixer/single-auth/pkg/logger"
	"go.uber.org/zap"
)

var (
	shutdownDelay = time.Second * 2
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	defer stop()

	cfg, err := config.Init()
	if err != nil {
		return fmt.Errorf("failed initialize config: %w", err)
	}

	lgr, err := logger.New(ctx, logger.SetLevel(cfg.LogLevel))
	if err != nil {
		return fmt.Errorf("failed initialize logger: %w", err)
	}

	cache, err := storage.NewCache(cfg.Cache)
	if err != nil {
		lgr.Error("failed initialize cache", zap.Error(err))
		return fmt.Errorf("failed initialize cache: %w", err)
	}

	store, err := storage.New(cfg.Store)
	if err != nil {
		lgr.Error("failed initialize storage", zap.Error(err))
		return fmt.Errorf("failed initialize storage: %w", err)
	}

	authManager, err := auth.New(lgr, []byte(cfg.SecretKey), store)
	if err != nil {
		return fmt.Errorf("failed initializa auth manager: %w", err)
	}

	adminManager := admin.New(store, lgr)

	httpServer := rest.New(
		authManager,
		adminManager,
		cache,
		lgr,
		rest.Addr(cfg.API.Addr),
		rest.BaseURL(cfg.API.BaseURL),
		rest.SetCookieDomain(cfg.API.CookieDomain.List()),
	)

	lgr.Info("Starting")
	go func() {
		err = httpServer.Run()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			lgr.Error("stop http server", zap.Error(err))
		}
	}()
	<-ctx.Done()
	lgr.Info("Stopping...")
	ctxShutdown, cancel := context.WithTimeout(context.Background(), shutdownDelay)
	defer cancel()

	httpServer.Stop() // отключаем http сервер.
	// short.Wait()      // ждем завершения горитин.
	store.Close() // закрываем соединение с бд.

	<-ctxShutdown.Done()
	lgr.Info("Service stoped")
	return nil
}
