# ampli-backend-go

Go rewrite of the Ampli API — free audio platform for creators to share podcasts, music, and audio content.

> Migrated from TypeScript/Express to Go 1.23 + Gin.

## Stack

| Layer | Technology |
|-------|-----------|
| Framework | [Gin](https://github.com/gin-gonic/gin) v1.10 |
| Database | MongoDB via [mongo-driver](https://github.com/mongodb/mongo-go-driver) v1.17 |
| Auth | [golang-jwt/jwt](https://github.com/golang-jwt/jwt) v5 — HS256, 24h expiry, token whitelist |
| Cloud storage | [cloudinary-go](https://github.com/cloudinary/cloudinary-go) v2 |
| Email | `net/smtp` (Mailtrap in dev) |
| Scheduler | [robfig/cron](https://github.com/robfig/cron) v3 — daily playlist generation at 00:00 ART |
| Logging | `log/slog` (Go 1.21+ stdlib) |
| Rate limiting | `golang.org/x/time/rate` — per-IP in-memory store |

## Project structure

```
cmd/server/main.go          # entry point
internal/
  config/config.go          # environment variables
  db/mongo.go               # MongoDB connection
  models/                   # BSON structs: user, audio, playlist, favorite, history, token
  middleware/               # auth.go, ratelimit.go, logger.go
  cloud/cloudinary.go       # UploadAvatar, UploadPoster, UploadAudio, Destroy*
  mail/mailer.go            # transactional email via SMTP
  utils/pagination.go       # ParsePagination helper
  auth/handler.go           # /auth routes + MongoDB index setup
  audio/handler.go          # /audio routes
  profile/handler.go        # /profile routes
  playlist/handler.go       # /playlist routes
  favorite/handler.go       # /favorite routes
  history/handler.go        # /history routes
  search/handler.go         # /search routes
  scheduler/playlist.go     # cron job: auto-generated playlists by category
```

## Getting started

```bash
# 1. Copy env file and fill in your values
cp .env.example .env

# 2. Download dependencies
go mod tidy

# 3. Run in development
go run cmd/server/main.go

# 4. Build for production
go build -o bin/ampli-api ./cmd/server
./bin/ampli-api
```

## Environment variables

See `.env.example` for the full list. Required variables:

| Variable | Description |
|----------|-------------|
| `MONGO_URI` | MongoDB connection string |
| `JWT_SECRET` | Secret key for signing JWTs |
| `CLOUD_NAME` / `CLOUD_KEY` / `CLOUD_SECRET` | Cloudinary credentials |
| `MAILTRAP_*` | SMTP credentials (Mailtrap for dev) |
| `PASSWORD_RESET_LINK` | Frontend URL for password reset |

## API endpoints

| Domain | Prefix | Endpoints |
|--------|--------|-----------|
| Auth | `/auth` | register, verify email, sign in/out, password reset, profile |
| Audio | `/audio` | create, update, delete, latest |
| Profile | `/profile` | public profile, uploads, follow, recommendations |
| Playlist | `/playlist` | create, update, delete, list |
| Favorite | `/favorite` | toggle, list, check |
| History | `/history` | update, remove, list, recently played |
| Search | `/search` | audios, users, playlists |
| Health | `/health` | status check |
