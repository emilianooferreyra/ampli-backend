package history

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"ampli/api/internal/middleware"
	"ampli/api/internal/models"

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
	g := r.Group("/history")
	g.Use(auth.RequireAuth())

	g.POST("", h.UpdateHistory)
	g.DELETE("", h.RemoveHistory)
	g.GET("", h.GetHistories)
	g.GET("/recently-played", h.GetRecentlyPlayed)
}

type updateHistoryReq struct {
	Audio    string    `json:"audio" binding:"required"`
	Progress float64   `json:"progress"`
	Date     time.Time `json:"date" binding:"required"`
}

// UpdateHistory adds or updates a history entry for the current user.
// POST /history
func (h *Handler) UpdateHistory(c *gin.Context) {
	var req updateHistoryReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	audioID, err := primitive.ObjectIDFromHex(req.Audio)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid audio id!"})
		return
	}

	profile := middleware.GetUser(c)
	ownerID, _ := primitive.ObjectIDFromHex(profile.ID)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	histories := h.db.Collection(models.HistoriesCollection)

	histItem := models.HistoryItem{
		ID:       primitive.NewObjectID(),
		Audio:    audioID,
		Progress: req.Progress,
		Date:     req.Date,
	}

	var existing models.History
	err = histories.FindOne(ctx, bson.M{"owner": ownerID}).Decode(&existing)
	if err != nil {
		// No history yet — create
		histories.InsertOne(ctx, models.History{ //nolint:errcheck
			ID:    primitive.NewObjectID(),
			Owner: ownerID,
			Last:  &histItem,
			All:   []models.HistoryItem{histItem},
		})
		c.JSON(http.StatusOK, gin.H{"success": true})
		return
	}

	// Check if this audio was already listened today
	today := req.Date
	startOfDay := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, today.Location())
	endOfDay := startOfDay.Add(24 * time.Hour)

	type audioIDResult struct {
		AudioID primitive.ObjectID `bson:"audioId"`
	}

	cursor, _ := histories.Aggregate(ctx, mongo.Pipeline{
		{{Key: "$match", Value: bson.D{{Key: "owner", Value: ownerID}}}},
		{{Key: "$unwind", Value: "$all"}},
		{{Key: "$match", Value: bson.D{{Key: "all.date", Value: bson.D{
			{Key: "$gte", Value: startOfDay},
			{Key: "$lt", Value: endOfDay},
		}}}}},
		{{Key: "$project", Value: bson.D{{Key: "_id", Value: 0}, {Key: "audioId", Value: "$all.audio"}}}},
	})

	var todayHistories []audioIDResult
	if cursor != nil {
		cursor.All(ctx, &todayHistories) //nolint:errcheck
		cursor.Close(ctx)
	}

	sameDayEntry := false
	for _, entry := range todayHistories {
		if entry.AudioID == audioID {
			sameDayEntry = true
			break
		}
	}

	if sameDayEntry {
		// Update progress for that entry
		histories.FindOneAndUpdate(ctx, //nolint:errcheck
			bson.M{"owner": ownerID, "all.audio": audioID},
			bson.M{"$set": bson.M{
				"all.$.progress": req.Progress,
				"all.$.date":     req.Date,
			}},
		)
	} else {
		// Prepend new entry
		histories.UpdateOne(ctx, bson.M{"_id": existing.ID}, bson.M{ //nolint:errcheck
			"$push": bson.M{"all": bson.M{"$each": []models.HistoryItem{histItem}, "$position": 0}},
			"$set":  bson.M{"last": histItem},
		})
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// RemoveHistory deletes all history or specific entries.
// DELETE /history?all=yes  or  DELETE /history?histories=[...]
func (h *Handler) RemoveHistory(c *gin.Context) {
	profile := middleware.GetUser(c)
	ownerID, _ := primitive.ObjectIDFromHex(profile.ID)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	histories := h.db.Collection(models.HistoriesCollection)

	if c.Query("all") == "yes" {
		histories.DeleteOne(ctx, bson.M{"owner": ownerID}) //nolint:errcheck
		c.JSON(http.StatusOK, gin.H{"success": true})
		return
	}

	historiesParam := c.Query("histories")
	if historiesParam == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing histories parameter"})
		return
	}

	var ids []string
	if err := json.Unmarshal([]byte(historiesParam), &ids); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid histories format"})
		return
	}

	objectIDs := make([]primitive.ObjectID, 0, len(ids))
	for _, id := range ids {
		oid, err := primitive.ObjectIDFromHex(id)
		if err == nil {
			objectIDs = append(objectIDs, oid)
		}
	}

	histories.UpdateOne(ctx, bson.M{"owner": ownerID}, //nolint:errcheck
		bson.M{"$pull": bson.M{"all": bson.M{"_id": bson.M{"$in": objectIDs}}}},
	)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// GetHistories returns paginated history grouped by date.
// GET /history
func (h *Handler) GetHistories(c *gin.Context) {
	profile := middleware.GetUser(c)
	ownerID, _ := primitive.ObjectIDFromHex(profile.ID)

	limit := c.DefaultQuery("limit", "20")
	pageNumber := c.DefaultQuery("pageNumber", "0")

	// parse as int for $slice
	var lim, page int64 = 20, 0
	if v, ok := parseInt(limit); ok {
		lim = v
	}
	if v, ok := parseInt(pageNumber); ok {
		page = v
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{{Key: "owner", Value: ownerID}}}},
		{{Key: "$project", Value: bson.D{
			{Key: "all", Value: bson.D{{Key: "$slice", Value: bson.A{"$all", lim * page, lim}}}},
		}}},
		{{Key: "$unwind", Value: "$all"}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "audios"},
			{Key: "localField", Value: "all.audio"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "audioInfo"},
		}}},
		{{Key: "$unwind", Value: "$audioInfo"}},
		{{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 0},
			{Key: "id", Value: "$all._id"},
			{Key: "audioId", Value: "$audioInfo._id"},
			{Key: "date", Value: "$all.date"},
			{Key: "title", Value: "$audioInfo.title"},
		}}},
		{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: bson.D{{Key: "$dateToString", Value: bson.D{
				{Key: "format", Value: "%Y-%m-%d"},
				{Key: "date", Value: "$date"},
			}}}},
			{Key: "audios", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}},
		}}},
		{{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 0},
			{Key: "date", Value: "$_id"},
			{Key: "audios", Value: "$$ROOT.audios"},
		}}},
		{{Key: "$sort", Value: bson.D{{Key: "date", Value: -1}}}},
	}

	cursor, err := h.db.Collection(models.HistoriesCollection).Aggregate(ctx, pipeline)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch histories"})
		return
	}
	defer cursor.Close(ctx)

	var histories []bson.M
	cursor.All(ctx, &histories) //nolint:errcheck
	if histories == nil {
		histories = []bson.M{}
	}
	c.JSON(http.StatusOK, gin.H{"histories": histories})
}

// GetRecentlyPlayed returns the 10 most recently played audios.
// GET /history/recently-played
func (h *Handler) GetRecentlyPlayed(c *gin.Context) {
	profile := middleware.GetUser(c)
	ownerID, _ := primitive.ObjectIDFromHex(profile.ID)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{{Key: "owner", Value: ownerID}}}},
		{{Key: "$project", Value: bson.D{{Key: "myHistory", Value: bson.D{{Key: "$slice", Value: bson.A{"$all", 10}}}}}}},
		{{Key: "$project", Value: bson.D{{Key: "histories", Value: bson.D{
			{Key: "$sortArray", Value: bson.D{
				{Key: "input", Value: "$myHistory"},
				{Key: "sortBy", Value: bson.D{{Key: "date", Value: -1}}},
			}},
		}}}}},
		{{Key: "$unwind", Value: bson.D{
			{Key: "path", Value: "$histories"},
			{Key: "includeArrayIndex", Value: "index"},
		}}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "audios"},
			{Key: "localField", Value: "histories.audio"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "audioInfo"},
		}}},
		{{Key: "$unwind", Value: "$audioInfo"}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "users"},
			{Key: "localField", Value: "audioInfo.owner"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "owner"},
		}}},
		{{Key: "$unwind", Value: "$owner"}},
		{{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 0},
			{Key: "id", Value: "$audioInfo._id"},
			{Key: "title", Value: "$audioInfo.title"},
			{Key: "about", Value: "$audioInfo.about"},
			{Key: "file", Value: "$audioInfo.file.url"},
			{Key: "poster", Value: "$audioInfo.poster.url"},
			{Key: "category", Value: "$audioInfo.category"},
			{Key: "owner", Value: bson.D{
				{Key: "name", Value: "$owner.name"},
				{Key: "id", Value: "$owner._id"},
			}},
			{Key: "date", Value: "$histories.date"},
			{Key: "progress", Value: "$histories.progress"},
		}}},
	}

	cursor, err := h.db.Collection(models.HistoriesCollection).Aggregate(ctx, pipeline)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch recently played"})
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

func parseInt(s string) (int64, bool) {
	v, err := strconv.ParseInt(s, 10, 64)
	return v, err == nil
}
