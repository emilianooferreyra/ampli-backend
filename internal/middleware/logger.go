package middleware

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

// Logger is a structured request logger using slog (stdlib Go 1.21+).
// Replaces pino-http.
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		duration := time.Since(start)
		status := c.Writer.Status()

		attrs := []any{
			slog.String("method", c.Request.Method),
			slog.String("path", path),
			slog.Int("status", status),
			slog.Duration("latency", duration),
			slog.String("ip", c.ClientIP()),
		}
		if query != "" {
			attrs = append(attrs, slog.String("query", query))
		}
		if errs := c.Errors.ByType(gin.ErrorTypePrivate); len(errs) > 0 {
			attrs = append(attrs, slog.String("errors", errs.String()))
		}

		if status >= 500 {
			slog.Error("request", attrs...)
		} else if status >= 400 {
			slog.Warn("request", attrs...)
		} else {
			slog.Info("request", attrs...)
		}
	}
}
