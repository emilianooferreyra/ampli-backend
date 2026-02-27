package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ampli/api/internal/auth"
	"ampli/api/internal/audio"
	"ampli/api/internal/cloud"
	"ampli/api/internal/config"
	"ampli/api/internal/db"
	"ampli/api/internal/favorite"
	"ampli/api/internal/history"
	"ampli/api/internal/middleware"
	"ampli/api/internal/playlist"
	"ampli/api/internal/profile"
	"ampli/api/internal/scheduler"
	"ampli/api/internal/search"

	"github.com/clerk/clerk-sdk-go/v2"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env (ignored in production if not present)
	_ = godotenv.Load()

	cfg := config.Load()

	// Initialize Clerk — reads CLERK_SECRET_KEY from env automatically,
	// but we set it explicitly so a missing key fails fast.
	clerk.SetKey(cfg.ClerkSecretKey)

	// Structured logger (replaces pino)
	var handler slog.Handler
	if cfg.IsDev() {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	} else {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	slog.SetDefault(slog.New(handler))

	// Database
	database := db.Connect(cfg.MongoURI)
	defer db.Disconnect(database)

	// Create MongoDB indexes at startup
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	auth.EnsureIndexes(ctx, database)
	cancel()

	// External clients
	cloudClient := cloud.New(cfg)

	// Gin setup
	if !cfg.IsDev() {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.Logger())
	r.Use(middleware.GlobalRateLimit())
	r.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.AllowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           86400 * time.Second,
	}))

	// Health endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "timestamp": time.Now().UTC()})
	})

	// Serve static files
	r.Static("/public", "./public")

	// Auth middleware (shared across handlers)
	authMiddleware := middleware.NewAuth(database, cfg)

	// Register domain handlers
	auth.NewHandler(database, cloudClient, nil, nil).RegisterRoutes(r, authMiddleware)
	audio.NewHandler(database, cloudClient).RegisterRoutes(r, authMiddleware)
	profile.NewHandler(database).RegisterRoutes(r, authMiddleware)
	playlist.NewHandler(database).RegisterRoutes(r, authMiddleware)
	favorite.NewHandler(database).RegisterRoutes(r, authMiddleware)
	history.NewHandler(database).RegisterRoutes(r, authMiddleware)
	search.NewHandler(database).RegisterRoutes(r)

	// Background jobs
	scheduler.Start(database)

	// HTTP server with timeouts
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start in background goroutine
	go func() {
		slog.Info("server listening", "port", cfg.Port, "env", cfg.Env)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown on SIGINT / SIGTERM
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutdown signal received, draining connections...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("forced shutdown", "err", err)
	}
	slog.Info("server stopped cleanly")
}
