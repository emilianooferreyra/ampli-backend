package playlist

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
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Handler struct {
	db *mongo.Database
}

func NewHandler(db *mongo.Database) *Handler {
	return &Handler{db: db}
}

func (h *Handler) RegisterRoutes(r *gin.Engine, auth *middleware.Auth) {
	g := r.Group("/playlist")
	g.Use(auth.RequireAuth())

	g.POST("/create", h.CreatePlaylist)
	g.PATCH("", h.UpdatePlaylist)
	g.DELETE("", h.RemovePlaylist)
	g.GET("/by-profile", h.GetPlaylistByProfile)
	g.GET("/:playlistId", h.GetAudios)
}

type createPlaylistReq struct {
	Title          string `json:"title" binding:"required"`
	InitialAudioID string `json:"initialAudioId"`
	Visibility     string `json:"visibility" binding:"required,oneof=public private"`
}

type updatePlaylistReq struct {
	ID         string `json:"id" binding:"required"`
	AddAudioID string `json:"addAudioId"`
	Title      string `json:"title"`
	Visibility string `json:"visibility"`
}

// CreatePlaylist creates a new playlist, optionally seeding it with one audio.
// POST /playlist/create
func (h *Handler) CreatePlaylist(c *gin.Context) {
	var req createPlaylistReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	profile := middleware.GetUser(c)
	ownerID, _ := primitive.ObjectIDFromHex(profile.ID)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	pl := models.Playlist{
		ID:         primitive.NewObjectID(),
		Title:      req.Title,
		Owner:      ownerID,
		Items:      []primitive.ObjectID{},
		Visibility: req.Visibility,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if req.InitialAudioID != "" {
		audioID, err := primitive.ObjectIDFromHex(req.InitialAudioID)
		if err == nil {
			count, _ := h.db.Collection(models.AudiosCollection).CountDocuments(ctx, bson.M{"_id": audioID})
			if count == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "Could not found the audio!"})
				return
			}
			pl.Items = []primitive.ObjectID{audioID}
		}
	}

	if _, err := h.db.Collection(models.PlaylistsCollection).InsertOne(ctx, pl); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create playlist"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"playlist": gin.H{"id": pl.ID.Hex(), "title": pl.Title, "visibility": pl.Visibility},
	})
}

// UpdatePlaylist updates title/visibility and optionally adds an audio.
// PATCH /playlist
func (h *Handler) UpdatePlaylist(c *gin.Context) {
	var req updatePlaylistReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	plID, err := primitive.ObjectIDFromHex(req.ID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid playlist id!"})
		return
	}

	profile := middleware.GetUser(c)
	ownerID, _ := primitive.ObjectIDFromHex(profile.ID)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	playlists := h.db.Collection(models.PlaylistsCollection)

	setFields := bson.M{"updatedAt": time.Now()}
	if req.Title != "" {
		setFields["title"] = req.Title
	}
	if req.Visibility != "" {
		setFields["visibility"] = req.Visibility
	}

	var pl models.Playlist
	err = playlists.FindOneAndUpdate(ctx,
		bson.M{"_id": plID, "owner": ownerID},
		bson.M{"$set": setFields},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	).Decode(&pl)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Playlist not found!"})
		return
	}

	if req.AddAudioID != "" {
		audioID, err := primitive.ObjectIDFromHex(req.AddAudioID)
		if err == nil {
			count, _ := h.db.Collection(models.AudiosCollection).CountDocuments(ctx, bson.M{"_id": audioID})
			if count == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "Audio not found!"})
				return
			}
			playlists.UpdateOne(ctx, bson.M{"_id": pl.ID}, bson.M{"$addToSet": bson.M{"items": audioID}}) //nolint:errcheck
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"playlist": gin.H{"id": pl.ID.Hex(), "title": pl.Title, "visibility": pl.Visibility},
	})
}

// RemovePlaylist deletes a playlist or removes a single audio from it.
// DELETE /playlist?playlistId=&removeAudioId=&all=yes
func (h *Handler) RemovePlaylist(c *gin.Context) {
	plIDStr := c.Query("playlistId")
	plID, err := primitive.ObjectIDFromHex(plIDStr)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid playlist id!"})
		return
	}

	profile := middleware.GetUser(c)
	ownerID, _ := primitive.ObjectIDFromHex(profile.ID)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	playlists := h.db.Collection(models.PlaylistsCollection)

	if c.Query("all") == "yes" {
		result, err := playlists.DeleteOne(ctx, bson.M{"_id": plID, "owner": ownerID})
		if err != nil || result.DeletedCount == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Playlist not found!"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true})
		return
	}

	removeAudioIDStr := c.Query("removeAudioId")
	if removeAudioIDStr != "" {
		audioID, err := primitive.ObjectIDFromHex(removeAudioIDStr)
		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid audio id!"})
			return
		}
		result, err := playlists.UpdateOne(ctx,
			bson.M{"_id": plID, "owner": ownerID},
			bson.M{"$pull": bson.M{"items": audioID}},
		)
		if err != nil || result.MatchedCount == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Playlist not found!"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// GetPlaylistByProfile returns the current user's playlists (excluding auto-generated).
// GET /playlist/by-profile
func (h *Handler) GetPlaylistByProfile(c *gin.Context) {
	profile := middleware.GetUser(c)
	ownerID, _ := primitive.ObjectIDFromHex(profile.ID)

	pg := utils.ParsePagination(c.Query("limit"), c.Query("pageNumber"))

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	opts := options.Find().
		SetSkip(pg.Skip).
		SetLimit(pg.Limit).
		SetSort(bson.D{{Key: "createdAt", Value: -1}})

	cursor, err := h.db.Collection(models.PlaylistsCollection).Find(ctx,
		bson.M{"owner": ownerID, "visibility": bson.M{"$ne": "auto"}},
		opts,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch playlists"})
		return
	}
	defer cursor.Close(ctx)

	var items []models.Playlist
	cursor.All(ctx, &items) //nolint:errcheck

	result := make([]gin.H, 0, len(items))
	for _, pl := range items {
		result = append(result, gin.H{
			"id":         pl.ID.Hex(),
			"title":      pl.Title,
			"itemsCount": len(pl.Items),
			"visibility": pl.Visibility,
		})
	}
	c.JSON(http.StatusOK, gin.H{"playlist": result})
}

// GetAudios returns the audios inside a user's playlist (with populated audio info).
// GET /playlist/:playlistId
func (h *Handler) GetAudios(c *gin.Context) {
	plIDStr := c.Param("playlistId")
	plID, err := primitive.ObjectIDFromHex(plIDStr)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid playlist id!"})
		return
	}

	profile := middleware.GetUser(c)
	ownerID, _ := primitive.ObjectIDFromHex(profile.ID)

	pg := utils.ParsePagination(c.Query("limit"), c.Query("pageNumber"))

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	pipeline := buildPlaylistAudiosPipeline(plID, ownerID, pg.Skip, pg.Limit, true)

	cursor, err := h.db.Collection(models.PlaylistsCollection).Aggregate(ctx, pipeline)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch playlist"})
		return
	}
	defer cursor.Close(ctx)

	var results []bson.M
	cursor.All(ctx, &results) //nolint:errcheck

	if len(results) == 0 {
		c.JSON(http.StatusOK, gin.H{"list": nil})
		return
	}
	c.JSON(http.StatusOK, gin.H{"list": results[0]})
}

// buildPlaylistAudiosPipeline creates the aggregation pipeline for playlist audio population.
func buildPlaylistAudiosPipeline(plID, ownerID primitive.ObjectID, skip, limit int64, privateOwner bool) mongo.Pipeline {
	matchFilter := bson.D{{Key: "_id", Value: plID}}
	if privateOwner {
		matchFilter = append(matchFilter, bson.E{Key: "owner", Value: ownerID})
	} else {
		matchFilter = append(matchFilter, bson.E{Key: "visibility", Value: bson.D{{Key: "$ne", Value: "private"}}})
	}

	return mongo.Pipeline{
		{{Key: "$match", Value: matchFilter}},
		{{Key: "$project", Value: bson.D{
			{Key: "items", Value: bson.D{
				{Key: "$slice", Value: bson.A{"$items", skip, limit}},
			}},
			{Key: "title", Value: "$title"},
		}}},
		{{Key: "$unwind", Value: "$items"}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "audios"},
			{Key: "localField", Value: "items"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "audios"},
		}}},
		{{Key: "$unwind", Value: "$audios"}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "users"},
			{Key: "localField", Value: "audios.owner"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "userInfo"},
		}}},
		{{Key: "$unwind", Value: "$userInfo"}},
		{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: bson.D{{Key: "title", Value: "$title"}, {Key: "id", Value: "$_id"}}},
			{Key: "audios", Value: bson.D{{Key: "$push", Value: bson.D{
				{Key: "id", Value: "$audios._id"},
				{Key: "title", Value: "$audios.title"},
				{Key: "about", Value: "$audios.about"},
				{Key: "file", Value: "$audios.file.url"},
				{Key: "poster", Value: "$audios.poster.url"},
				{Key: "category", Value: "$audios.category"},
				{Key: "owner", Value: bson.D{
					{Key: "name", Value: "$userInfo.name"},
					{Key: "id", Value: "$userInfo._id"},
				}},
			}}}},
		}}},
		{{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 0},
			{Key: "id", Value: "$_id.id"},
			{Key: "title", Value: "$_id.title"},
			{Key: "audios", Value: "$$ROOT.audios"},
		}}},
	}
}
