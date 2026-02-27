package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"ampli/api/internal/models"

	clerkjwt "github.com/clerk/clerk-sdk-go/v2/jwt"
	clerkuser "github.com/clerk/clerk-sdk-go/v2/user"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// contextKey is a private type to avoid collisions in context values.
type contextKey string

const (
	UserKey contextKey = "user"
)

// Auth holds the MongoDB database reference for user lookups.
type Auth struct {
	db *mongo.Database
}

// NewAuth accepts (db, cfg) to keep backward compatibility with existing call
// sites in main.go; the config is no longer used since Clerk reads its secret
// key from the CLERK_SECRET_KEY environment variable automatically.
func NewAuth(db *mongo.Database, _ interface{}) *Auth {
	return &Auth{db: db}
}

// RequireAuth validates the Clerk Bearer JWT and attaches the user to context.
// On first access it lazily creates a MongoDB user document for the Clerk user.
func (a *Auth) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractBearerToken(c)
		if token == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Unauthorized request!"})
			return
		}

		claims, err := clerkjwt.Verify(c.Request.Context(), &clerkjwt.VerifyParams{
			Token: token,
		})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Unauthorized request!"})
			return
		}

		user, err := a.findOrCreateUser(c.Request.Context(), claims.Subject)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		c.Set(string(UserKey), user.ToProfile())
		c.Next()
	}
}

// IsAuth is an optional auth middleware — attaches user if token is valid,
// but does not abort if no token is present.
func (a *Auth) IsAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractBearerToken(c)
		if token != "" {
			claims, err := clerkjwt.Verify(c.Request.Context(), &clerkjwt.VerifyParams{
				Token: token,
			})
			if err == nil {
				if user, err := a.findOrCreateUser(c.Request.Context(), claims.Subject); err == nil {
					c.Set(string(UserKey), user.ToProfile())
				}
			}
		}
		c.Next()
	}
}

// IsVerified aborts if the user has not verified their email.
// All Clerk users have verified their email before sign-in, so this always
// passes for Clerk-authenticated users (Verified is set to true on creation).
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

// --- helpers ---

func extractBearerToken(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	parts := strings.SplitN(auth, "Bearer ", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// findOrCreateUser looks up a MongoDB user by their Clerk ID.
// If no document exists yet, it creates one using Clerk's user API to
// pre-populate name and email.
func (a *Auth) findOrCreateUser(ctx context.Context, clerkID string) (*models.User, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var user models.User
	err := a.db.Collection(models.UsersCollection).
		FindOne(ctx, bson.M{"clerkId": clerkID}).
		Decode(&user)

	if err != mongo.ErrNoDocuments {
		return &user, err
	}

	// New user: fetch profile info from Clerk to populate the document.
	now := time.Now()
	user = models.User{
		ClerkID:    clerkID,
		Verified:   true,
		Favorites:  []primitive.ObjectID{},
		Followers:  []primitive.ObjectID{},
		Followings: []primitive.ObjectID{},
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	clerkUser, clerkErr := clerkuser.Get(ctx, clerkID)
	if clerkErr == nil && clerkUser != nil {
		if clerkUser.FirstName != nil {
			user.Name = *clerkUser.FirstName
			if clerkUser.LastName != nil {
				user.Name += " " + *clerkUser.LastName
			}
		}
		if clerkUser.PrimaryEmailAddressID != nil {
			for _, addr := range clerkUser.EmailAddresses {
				if addr.ID == *clerkUser.PrimaryEmailAddressID {
					user.Email = addr.EmailAddress
					break
				}
			}
		}
	}

	result, insertErr := a.db.Collection(models.UsersCollection).InsertOne(ctx, user)
	if insertErr != nil {
		return nil, insertErr
	}
	user.ID = result.InsertedID.(primitive.ObjectID)
	return &user, nil
}
