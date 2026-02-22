# ampli-backend-go Memory

## Project
Go rewrite of `ampli-backend` (TypeScript/Express) using Gin framework.

## Stack
- Framework: Gin v1.10
- DB: MongoDB via mongo-driver v1.17 (database name: "intune")
- Auth: golang-jwt/jwt/v5 (HS256, 24h expiry, token whitelist in DB)
- Cloud: cloudinary-go/v2 (Transformation string format, not struct fields)
- Mail: net/smtp (Mailtrap in dev)
- Scheduler: robfig/cron/v3 (daily at 00:00 ART)
- Logging: log/slog (stdlib Go 1.21+)
- Rate limiting: golang.org/x/time/rate (per-IP in-memory store)

## Module path
`ampli/api`

## Structure
```
cmd/server/main.go          -- entry point
internal/
  config/config.go          -- env vars
  db/mongo.go               -- connection
  models/                   -- BSON structs (user, audio, playlist, favorite, history, token)
  middleware/               -- auth.go, ratelimit.go, logger.go
  cloud/cloudinary.go       -- UploadAvatar, UploadPoster, UploadAudio, DestroyImage/Audio
  mail/mailer.go            -- SMTP email
  utils/pagination.go       -- ParsePagination
  auth/handler.go           -- RegisterRoutes + EnsureIndexes
  audio/handler.go
  profile/handler.go
  playlist/handler.go
  favorite/handler.go
  history/handler.go
  search/handler.go
  scheduler/playlist.go
```

## Key patterns
- Handler struct per domain: `type Handler struct { db *mongo.Database; ... }`
- `RegisterRoutes(r *gin.Engine, auth *middleware.Auth)` on each handler
- Middleware: `auth.RequireAuth()`, `auth.IsAuth()`, `middleware.IsVerified()`
- `middleware.GetUser(c)` returns `*models.UserProfile` from context
- `middleware.GetToken(c)` returns raw JWT string from context
- MongoDB indexes created at startup via `auth.EnsureIndexes(ctx, db)`
- TTL indexes on email/password reset tokens (3600s)
- Cloudinary uses Transformation string: "c_thumb,w_300,h_300,g_face"

## Build
```bash
cd ampli-backend-go
go mod tidy     # first time
go build ./...  # verify
go run cmd/server/main.go
```
