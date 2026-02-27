package auth

import (
	"context"
	"net/http"
	"time"

	"ampli/api/internal/cloud"
	"ampli/api/internal/middleware"
	"ampli/api/internal/models"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Handler contains auth-related route handlers.
// Authentication (sign-in, sign-up, password reset, email verification) is
// fully delegated to Clerk — only profile management lives here.
type Handler struct {
	db    *mongo.Database
	cloud *cloud.Client
}

func NewHandler(db *mongo.Database, cloudClient *cloud.Client, _ interface{}, _ interface{}) *Handler {
	return &Handler{db: db, cloud: cloudClient}
}

// RegisterRoutes wires /auth routes.
func (h *Handler) RegisterRoutes(r *gin.Engine, auth *middleware.Auth) {
	g := r.Group("/auth")

	g.GET("/is-auth", auth.RequireAuth(), h.SendProfile)
	g.POST("/update-profile", auth.RequireAuth(), h.UpdateProfile)
}

// SendProfile returns the authenticated user's profile.
// GET /auth/is-auth
func (h *Handler) SendProfile(c *gin.Context) {
	profile := middleware.GetUser(c)
	c.JSON(http.StatusOK, gin.H{"profile": profile})
}

// UpdateProfile updates name and/or avatar.
// POST /auth/update-profile
func (h *Handler) UpdateProfile(c *gin.Context) {
	profile := middleware.GetUser(c)

	name := c.PostForm("name")
	if len([]rune(name)) < 3 {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid name!"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	userID, _ := primitive.ObjectIDFromHex(profile.ID)
	users := h.db.Collection(models.UsersCollection)

	var user models.User
	if err := users.FindOne(ctx, bson.M{"_id": userID}).Decode(&user); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found!"})
		return
	}

	update := bson.M{"name": name, "updatedAt": time.Now()}

	file, header, err := c.Request.FormFile("avatar")
	if err == nil {
		defer file.Close()

		if user.Avatar != nil && user.Avatar.PublicID != "" {
			h.cloud.DestroyImage(ctx, user.Avatar.PublicID) //nolint:errcheck
		}

		result, err := h.cloud.UploadAvatar(ctx, file)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload avatar"})
			return
		}
		_ = header
		update["avatar"] = models.Avatar{URL: result.URL, PublicID: result.PublicID}
	}

	users.UpdateOne(ctx, bson.M{"_id": userID}, bson.M{"$set": update}) //nolint:errcheck

	users.FindOne(ctx, bson.M{"_id": userID}).Decode(&user) //nolint:errcheck
	c.JSON(http.StatusOK, gin.H{"profile": user.ToProfile()})
}

// EnsureIndexes creates MongoDB indexes required by the application.
func EnsureIndexes(ctx context.Context, db *mongo.Database) {
	db.Collection(models.UsersCollection).Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "clerkId", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetSparse(true)},
		{Keys: bson.D{{Key: "name", Value: "text"}}},
	}) //nolint:errcheck

	db.Collection(models.AudiosCollection).Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "title", Value: "text"}, {Key: "about", Value: "text"}}},
		{Keys: bson.D{{Key: "category", Value: 1}, {Key: "createdAt", Value: -1}}},
		{Keys: bson.D{{Key: "owner", Value: 1}, {Key: "createdAt", Value: -1}}},
	}) //nolint:errcheck
}
