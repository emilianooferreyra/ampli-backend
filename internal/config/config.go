package config

import (
	"os"
	"strings"
)

type Config struct {
	Port     string
	Env      string
	MongoURI string

	ClerkSecretKey string
	AllowedOrigins []string

	CloudName   string
	CloudKey    string
	CloudSecret string

	SMTPHost string
	SMTPPort string
	SMTPUser string
	SMTPPass string
	MailFrom  string
}

func Load() *Config {
	origins := []string{"http://localhost:3000"}
	if raw := os.Getenv("ALLOWED_ORIGINS"); raw != "" {
		origins = strings.Split(raw, ",")
	}

	return &Config{
		Port:           getEnv("PORT", "8989"),
		Env:            getEnv("NODE_ENV", "development"),
		MongoURI:       os.Getenv("MONGO_URI"),
		ClerkSecretKey: os.Getenv("CLERK_SECRET_KEY"),
		AllowedOrigins: origins,

		CloudName:   os.Getenv("CLOUD_NAME"),
		CloudKey:    os.Getenv("CLOUD_KEY"),
		CloudSecret: os.Getenv("CLOUD_SECRET"),

		SMTPHost: os.Getenv("MAILTRAP_HOST"),
		SMTPPort: os.Getenv("MAILTRAP_PORT"),
		SMTPUser: os.Getenv("MAILTRAP_USER"),
		SMTPPass: os.Getenv("MAILTRAP_PASS"),
		MailFrom: getEnv("MAIL_FROM", "noreply@ampli.app"),
	}
}

func (c *Config) IsDev() bool {
	return c.Env == "development"
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
