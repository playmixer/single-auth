package main

import (
	"auth/internal/adapters/api/rest"
	"auth/internal/adapters/config"
	"auth/internal/adapters/storage"
	"auth/internal/core/auth"
	"auth/pkg/logger"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

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

	store, err := storage.New()
	if err != nil {
		lgr.Error("failed initialize storage", zap.Error(err))
		return fmt.Errorf("failed initialize storage: %w", err)
	}

	authManager, err := auth.New(lgr, []byte(cfg.SecretKey), store)
	if err != nil {
		return fmt.Errorf("failed initializa auth manager: %w", err)
	}

	httpServer := rest.New(
		authManager,
		lgr,
		rest.Addr(cfg.API.Addr),
		rest.BaseURL(cfg.API.BaseURL),
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
