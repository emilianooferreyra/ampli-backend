package favorite

import (
	"context"
	"net/http"
	"time"

	"ampli/api/internal/middleware"
	"ampli/api/internal/models"
	"ampli/api/internal/utils"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type Handler struct {
	db *mongo.Database
}

func NewHandler(db *mongo.Database) *Handler {
	return &Handler{db: db}
}

func (h *Handler) RegisterRoutes(r *gin.Engine, auth *middleware.Auth) {
	g := r.Group("/favorite")
	g.Use(auth.RequireAuth())

	g.POST("", h.ToggleFavorite)
	g.GET("", h.GetFavorites)
	g.GET("/is-fav", h.GetIsFavorite)
}

// ToggleFavorite adds or removes an audio from the user's favorites.
// POST /favorite?audioId=...
func (h *Handler) ToggleFavorite(c *gin.Context) {
	audioIDStr := c.Query("audioId")
	audioID, err := primitive.ObjectIDFromHex(audioIDStr)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Audio id is invalid!"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// Check audio exists
	count, _ := h.db.Collection(models.AudiosCollection).CountDocuments(ctx, bson.M{"_id": audioID})
	if count == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Resources not found!"})
		return
	}

	profile := middleware.GetUser(c)
	ownerID, _ := primitive.ObjectIDFromHex(profile.ID)
	favs := h.db.Collection(models.FavoritesCollection)
	audios := h.db.Collection(models.AudiosCollection)

	// Check if already favorited
	existing, _ := favs.CountDocuments(ctx, bson.M{"owner": ownerID, "items": audioID})

	var status string
	if existing > 0 {
		favs.UpdateOne(ctx, bson.M{"owner": ownerID}, bson.M{"$pull": bson.M{"items": audioID}}) //nolint:errcheck
		audios.UpdateOne(ctx, bson.M{"_id": audioID}, bson.M{"$pull": bson.M{"likes": ownerID}}) //nolint:errcheck
		status = "removed"
	} else {
		// Upsert the favorites document
		fav, _ := favs.CountDocuments(ctx, bson.M{"owner": ownerID})
		if fav > 0 {
			favs.UpdateOne(ctx, bson.M{"owner": ownerID}, bson.M{"$addToSet": bson.M{"items": audioID}}) //nolint:errcheck
		} else {
			favs.InsertOne(ctx, models.Favorite{ID: primitive.NewObjectID(), Owner: ownerID, Items: []primitive.ObjectID{audioID}}) //nolint:errcheck
		}
		audios.UpdateOne(ctx, bson.M{"_id": audioID}, bson.M{"$addToSet": bson.M{"likes": ownerID}}) //nolint:errcheck
		status = "added"
	}

	c.JSON(http.StatusOK, gin.H{"status": status})
}

// GetFavorites returns a paginated list of the user's favorite audios.
// GET /favorite
func (h *Handler) GetFavorites(c *gin.Context) {
	profile := middleware.GetUser(c)
	ownerID, _ := primitive.ObjectIDFromHex(profile.ID)

	pg := utils.ParsePagination(c.Query("limit"), c.Query("pageNumber"))

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{{Key: "owner", Value: ownerID}}}},
		{{Key: "$project", Value: bson.D{
			{Key: "paginatedAudioIds", Value: bson.D{
				{Key: "$slice", Value: bson.A{"$items", pg.Skip, pg.Limit}},
			}},
		}}},
		{{Key: "$unwind", Value: "$paginatedAudioIds"}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "audios"},
			{Key: "localField", Value: "paginatedAudioIds"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "audioInfo"},
		}}},
		{{Key: "$unwind", Value: "$audioInfo"}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "users"},
			{Key: "localField", Value: "audioInfo.owner"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "ownerInfo"},
		}}},
		{{Key: "$unwind", Value: "$ownerInfo"}},
		{{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 0},
			{Key: "id", Value: "$audioInfo._id"},
			{Key: "title", Value: "$audioInfo.title"},
			{Key: "about", Value: "$audioInfo.about"},
			{Key: "file", Value: "$audioInfo.file.url"},
			{Key: "poster", Value: "$audioInfo.poster.url"},
			{Key: "category", Value: "$audioInfo.category"},
			{Key: "owner", Value: bson.D{
				{Key: "name", Value: "$ownerInfo.name"},
				{Key: "id", Value: "$ownerInfo._id"},
			}},
		}}},
	}

	cursor, err := h.db.Collection(models.FavoritesCollection).Aggregate(ctx, pipeline)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch favorites"})
		return
	}
	defer cursor.Close(ctx)

	var audios []bson.M
	cursor.All(ctx, &audios) //nolint:errcheck
	if audios == nil {
		audios = []bson.M{}
	}
	c.JSON(http.StatusOK, gin.H{"audios": audios})
}

// GetIsFavorite checks if an audio is in the user's favorites.
// GET /favorite/is-fav?audioId=...
func (h *Handler) GetIsFavorite(c *gin.Context) {
	audioIDStr := c.Query("audioId")
	audioID, err := primitive.ObjectIDFromHex(audioIDStr)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid audio id!"})
		return
	}

	profile := middleware.GetUser(c)
	ownerID, _ := primitive.ObjectIDFromHex(profile.ID)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	count, _ := h.db.Collection(models.FavoritesCollection).CountDocuments(ctx, bson.M{
		"owner": ownerID,
		"items": audioID,
	})
	c.JSON(http.StatusOK, gin.H{"result": count > 0})
}
