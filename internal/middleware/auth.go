package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"ampli/api/internal/config"
	"ampli/api/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// contextKey is a private type to avoid collisions in context values.
type contextKey string

const (
	UserKey  contextKey = "user"
	TokenKey contextKey = "token"
)

// Auth holds dependencies for JWT middleware.
type Auth struct {
	db  *mongo.Database
	cfg *config.Config
}

func NewAuth(db *mongo.Database, cfg *config.Config) *Auth {
	return &Auth{db: db, cfg: cfg}
}

// RequireAuth validates the Bearer JWT and attaches user to context.
// Mirrors the requireAuth middleware from TypeScript.
func (a *Auth) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractBearerToken(c)
		if token == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Unauthorized request!"})
			return
		}

		user, err := a.verifyAndLoadUser(c.Request.Context(), token)
		if err != nil {
			if err == jwt.ErrTokenExpired {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired, please sign in again."})
				return
			}
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Unauthorized request!"})
			return
		}

		c.Set(string(UserKey), user.ToProfile())
		c.Set(string(TokenKey), token)
		c.Next()
	}
}

// IsAuth is an optional auth middleware — attaches user if token is valid,
// but does not abort if no token is provided. Mirrors isAuth from TypeScript.
func (a *Auth) IsAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractBearerToken(c)
		if token != "" {
			user, err := a.verifyAndLoadUser(c.Request.Context(), token)
			if err == nil {
				c.Set(string(UserKey), user.ToProfile())
				c.Set(string(TokenKey), token)
			}
		}
		c.Next()
	}
}

// IsVerified aborts if the authenticated user has not verified their email.
func IsVerified() gin.HandlerFunc {
	return func(c *gin.Context) {
		profile := GetUser(c)
		if profile == nil || !profile.Verified {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Please verify your email account!"})
			return
		}
		c.Next()
	}
}

// GetUser retrieves the UserProfile from Gin context (set by RequireAuth/IsAuth).
func GetUser(c *gin.Context) *models.UserProfile {
	v, exists := c.Get(string(UserKey))
	if !exists {
		return nil
	}
	p, ok := v.(models.UserProfile)
	if !ok {
		return nil
	}
	return &p
}

// GetToken retrieves the raw JWT token string from Gin context.
func GetToken(c *gin.Context) string {
	v, _ := c.Get(string(TokenKey))
	t, _ := v.(string)
	return t
}

// --- helpers ---

func extractBearerToken(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	parts := strings.SplitN(auth, "Bearer ", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func (a *Auth) verifyAndLoadUser(ctx context.Context, tokenStr string) (*models.User, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		return []byte(a.cfg.JWTSecret), nil
	})
	if err != nil {
		return nil, err
	}

	userIDStr, ok := claims["userId"].(string)
	if !ok {
		return nil, jwt.ErrTokenMalformed
	}

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		return nil, jwt.ErrTokenMalformed
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var user models.User
	err = a.db.Collection(models.UsersCollection).FindOne(ctx, bson.M{
		"_id":    userID,
		"tokens": tokenStr,
	}).Decode(&user)
	if err != nil {
		return nil, jwt.ErrTokenMalformed
	}

	return &user, nil
}

// SignToken creates a new JWT for the given userID.
func SignToken(userID primitive.ObjectID, secret string) (string, error) {
	claims := jwt.MapClaims{
		"userId": userID.Hex(),
		"exp":    jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}
