package audio

import (
	"context"
	"net/http"
	"slices"
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

type Handler struct {
	db    *mongo.Database
	cloud *cloud.Client
}

func NewHandler(db *mongo.Database, cloud *cloud.Client) *Handler {
	return &Handler{db: db, cloud: cloud}
}

func (h *Handler) RegisterRoutes(r *gin.Engine, auth *middleware.Auth) {
	g := r.Group("/audio")

	g.POST("/create", middleware.UploadRateLimit(), auth.RequireAuth(), middleware.IsVerified(), h.CreateAudio)
	g.PATCH("/:audioId", middleware.UploadRateLimit(), auth.RequireAuth(), middleware.IsVerified(), h.UpdateAudio)
	g.DELETE("/:audioId", auth.RequireAuth(), middleware.IsVerified(), h.DeleteAudio)
	g.GET("/latest", h.GetLatestUploads)
}

type createAudioReq struct {
	Title    string `form:"title" binding:"required"`
	About    string `form:"about" binding:"required"`
	Category string `form:"category" binding:"required"`
}

// CreateAudio uploads audio (and optional poster) to Cloudinary and saves to DB.
// POST /audio/create
func (h *Handler) CreateAudio(c *gin.Context) {
	var req createAudioReq
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !slices.Contains(models.AudioCategories, req.Category) {
		req.Category = "Others"
	}

	audioFile, audioHeader, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Audio file is missing!"})
		return
	}
	defer audioFile.Close()
	_ = audioHeader

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	profile := middleware.GetUser(c)
	ownerID, _ := primitive.ObjectIDFromHex(profile.ID)

	// Upload audio to Cloudinary
	audioResult, err := h.cloud.UploadAudio(ctx, audioFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload audio"})
		return
	}

	newAudio := models.Audio{
		ID:        primitive.NewObjectID(),
		Title:     req.Title,
		About:     req.About,
		Category:  req.Category,
		Owner:     ownerID,
		File:      models.AudioFile{URL: audioResult.URL, PublicID: audioResult.PublicID},
		Likes:     []primitive.ObjectID{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Upload poster if provided
	posterFile, _, err := c.Request.FormFile("poster")
	if err == nil {
		defer posterFile.Close()
		posterResult, err := h.cloud.UploadPoster(ctx, posterFile)
		if err == nil {
			newAudio.Poster = &models.AudioFile{URL: posterResult.URL, PublicID: posterResult.PublicID}
		}
	}

	if _, err := h.db.Collection(models.AudiosCollection).InsertOne(ctx, newAudio); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save audio"})
		return
	}

	posterURL := ""
	if newAudio.Poster != nil {
		posterURL = newAudio.Poster.URL
	}

	c.JSON(http.StatusCreated, gin.H{
		"audio": gin.H{
			"title":  newAudio.Title,
			"about":  newAudio.About,
			"file":   newAudio.File.URL,
			"poster": posterURL,
		},
	})
}

// UpdateAudio updates metadata and optionally replaces the poster.
// PATCH /audio/:audioId
func (h *Handler) UpdateAudio(c *gin.Context) {
	audioIDStr := c.Param("audioId")
	audioID, err := primitive.ObjectIDFromHex(audioIDStr)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid audio id!"})
		return
	}

	var req createAudioReq
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !slices.Contains(models.AudioCategories, req.Category) {
		req.Category = "Others"
	}

	profile := middleware.GetUser(c)
	ownerID, _ := primitive.ObjectIDFromHex(profile.ID)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	audios := h.db.Collection(models.AudiosCollection)

	var audio models.Audio
	err = audios.FindOneAndUpdate(ctx,
		bson.M{"_id": audioID, "owner": ownerID},
		bson.M{"$set": bson.M{"title": req.Title, "about": req.About, "category": req.Category, "updatedAt": time.Now()}},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	).Decode(&audio)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Record not found!"})
		return
	}

	// Replace poster if provided
	posterFile, _, err := c.Request.FormFile("poster")
	if err == nil {
		defer posterFile.Close()

		if audio.Poster != nil && audio.Poster.PublicID != "" {
			h.cloud.DestroyImage(ctx, audio.Poster.PublicID) //nolint:errcheck
		}

		posterResult, err := h.cloud.UploadPoster(ctx, posterFile)
		if err == nil {
			poster := models.AudioFile{URL: posterResult.URL, PublicID: posterResult.PublicID}
			audio.Poster = &poster
			audios.UpdateOne(ctx, bson.M{"_id": audioID}, bson.M{"$set": bson.M{"poster": poster}}) //nolint:errcheck
		}
	}

	posterURL := ""
	if audio.Poster != nil {
		posterURL = audio.Poster.URL
	}

	c.JSON(http.StatusCreated, gin.H{
		"audio": gin.H{
			"title":  audio.Title,
			"about":  audio.About,
			"file":   audio.File.URL,
			"poster": posterURL,
		},
	})
}

// DeleteAudio removes an audio and its Cloudinary assets.
// DELETE /audio/:audioId
func (h *Handler) DeleteAudio(c *gin.Context) {
	audioIDStr := c.Param("audioId")
	audioID, err := primitive.ObjectIDFromHex(audioIDStr)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid audio id!"})
		return
	}

	profile := middleware.GetUser(c)
	ownerID, _ := primitive.ObjectIDFromHex(profile.ID)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	var audio models.Audio
	if err := h.db.Collection(models.AudiosCollection).
		FindOne(ctx, bson.M{"_id": audioID, "owner": ownerID}).
		Decode(&audio); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Audio not found!"})
		return
	}

	// Remove from Cloudinary
	if audio.File.PublicID != "" {
		h.cloud.DestroyAudio(ctx, audio.File.PublicID) //nolint:errcheck
	}
	if audio.Poster != nil && audio.Poster.PublicID != "" {
		h.cloud.DestroyImage(ctx, audio.Poster.PublicID) //nolint:errcheck
	}

	// Remove from playlists and favorites
	pull := bson.M{"$pull": bson.M{"items": audioID}}
	h.db.Collection(models.PlaylistsCollection).UpdateMany(ctx, bson.M{"items": audioID}, pull)   //nolint:errcheck
	h.db.Collection(models.FavoritesCollection).UpdateMany(ctx, bson.M{"items": audioID}, pull)   //nolint:errcheck

	h.db.Collection(models.AudiosCollection).DeleteOne(ctx, bson.M{"_id": audioID}) //nolint:errcheck

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Audio deleted successfully"})
}

// GetLatestUploads returns the 10 most recently uploaded audios.
// GET /audio/latest
func (h *Handler) GetLatestUploads(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	pipeline := mongo.Pipeline{
		{{Key: "$sort", Value: bson.D{{Key: "createdAt", Value: -1}}}},
		{{Key: "$limit", Value: 10}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "users"},
			{Key: "localField", Value: "owner"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "ownerData"},
		}}},
		{{Key: "$unwind", Value: bson.D{
			{Key: "path", Value: "$ownerData"},
			{Key: "preserveNullAndEmptyArrays", Value: true},
		}}},
		{{Key: "$project", Value: bson.D{
			{Key: "id", Value: "$_id"},
			{Key: "title", Value: 1},
			{Key: "about", Value: 1},
			{Key: "category", Value: 1},
			{Key: "file", Value: "$file.url"},
			{Key: "poster", Value: "$poster.url"},
			{Key: "owner", Value: bson.D{
				{Key: "name", Value: "$ownerData.name"},
				{Key: "id", Value: "$ownerData._id"},
			}},
		}}},
	}

	cursor, err := h.db.Collection(models.AudiosCollection).Aggregate(ctx, pipeline)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch audios"})
		return
	}
	defer cursor.Close(ctx)

	var audios []bson.M
	if err := cursor.All(ctx, &audios); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode audios"})
		return
	}

	if audios == nil {
		audios = []bson.M{}
	}
	c.JSON(http.StatusOK, gin.H{"audios": audios})
}
