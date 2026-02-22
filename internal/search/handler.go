package search

import (
	"context"
	"net/http"
	"time"

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

func (h *Handler) RegisterRoutes(r *gin.Engine) {
	g := r.Group("/search")

	g.GET("/audios", h.SearchAudios)
	g.GET("/users", h.SearchUsers)
	g.GET("/playlists", h.SearchPlaylists)
}

// SearchAudios searches audio by title/about with optional category filter.
// GET /search/audios?q=&category=&limit=&pageNumber=
func (h *Handler) SearchAudios(c *gin.Context) {
	q := c.Query("q")
	if q == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Search query is required!"})
		return
	}

	pg := utils.ParsePagination(c.Query("limit"), c.Query("pageNumber"))

	filter := bson.M{
		"$or": bson.A{
			bson.M{"title": primitive.Regex{Pattern: q, Options: "i"}},
			bson.M{"about": primitive.Regex{Pattern: q, Options: "i"}},
		},
	}
	if category := c.Query("category"); category != "" {
		filter["category"] = category
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	audios := h.db.Collection(models.AudiosCollection)

	total, _ := audios.CountDocuments(ctx, filter)

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: filter}},
		{{Key: "$sort", Value: bson.D{{Key: "createdAt", Value: -1}}}},
		{{Key: "$skip", Value: pg.Skip}},
		{{Key: "$limit", Value: pg.Limit}},
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
			{Key: "_id", Value: 0},
			{Key: "id", Value: "$_id"},
			{Key: "title", Value: 1},
			{Key: "about", Value: 1},
			{Key: "category", Value: 1},
			{Key: "file", Value: "$file.url"},
			{Key: "poster", Value: "$poster.url"},
			{Key: "owner", Value: bson.D{
				{Key: "name", Value: "$ownerData.name"},
				{Key: "id", Value: "$ownerData._id"},
				{Key: "avatar", Value: "$ownerData.avatar.url"},
			}},
		}}},
	}

	cursor, err := audios.Aggregate(ctx, pipeline)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search audios"})
		return
	}
	defer cursor.Close(ctx)

	var results []bson.M
	cursor.All(ctx, &results) //nolint:errcheck
	if results == nil {
		results = []bson.M{}
	}

	c.JSON(http.StatusOK, gin.H{
		"audios": results,
		"pagination": gin.H{
			"total": total,
			"page":  pg.PageNumber,
			"limit": pg.Limit,
			"pages": (total + pg.Limit - 1) / pg.Limit,
		},
	})
}

// SearchUsers searches users by name.
// GET /search/users?q=&limit=&pageNumber=
func (h *Handler) SearchUsers(c *gin.Context) {
	q := c.Query("q")
	if q == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Search query is required!"})
		return
	}

	pg := utils.ParsePagination(c.Query("limit"), c.Query("pageNumber"))

	filter := bson.M{"name": primitive.Regex{Pattern: q, Options: "i"}}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	usersCol := h.db.Collection(models.UsersCollection)
	total, _ := usersCol.CountDocuments(ctx, filter)

	opts := options.Find().
		SetSkip(pg.Skip).
		SetLimit(pg.Limit).
		SetProjection(bson.M{"name": 1, "avatar": 1, "followers": 1, "followings": 1})

	cursor, err := usersCol.Find(ctx, filter, opts)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search users"})
		return
	}
	defer cursor.Close(ctx)

	var users []models.User
	cursor.All(ctx, &users) //nolint:errcheck

	result := make([]gin.H, 0, len(users))
	for _, u := range users {
		avatarURL := ""
		if u.Avatar != nil {
			avatarURL = u.Avatar.URL
		}
		result = append(result, gin.H{
			"id":         u.ID.Hex(),
			"name":       u.Name,
			"avatar":     avatarURL,
			"followers":  len(u.Followers),
			"followings": len(u.Followings),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"users": result,
		"pagination": gin.H{
			"total": total,
			"page":  pg.PageNumber,
			"limit": pg.Limit,
			"pages": (total + pg.Limit - 1) / pg.Limit,
		},
	})
}

// SearchPlaylists searches public playlists by title.
// GET /search/playlists?q=&limit=&pageNumber=
func (h *Handler) SearchPlaylists(c *gin.Context) {
	q := c.Query("q")
	if q == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Search query is required!"})
		return
	}

	pg := utils.ParsePagination(c.Query("limit"), c.Query("pageNumber"))

	filter := bson.M{
		"title":      primitive.Regex{Pattern: q, Options: "i"},
		"visibility": "public",
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	playlistsCol := h.db.Collection(models.PlaylistsCollection)
	total, _ := playlistsCol.CountDocuments(ctx, filter)

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: filter}},
		{{Key: "$sort", Value: bson.D{{Key: "createdAt", Value: -1}}}},
		{{Key: "$skip", Value: pg.Skip}},
		{{Key: "$limit", Value: pg.Limit}},
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
			{Key: "_id", Value: 0},
			{Key: "id", Value: "$_id"},
			{Key: "title", Value: 1},
			{Key: "itemsCount", Value: bson.D{{Key: "$size", Value: "$items"}}},
			{Key: "visibility", Value: 1},
			{Key: "owner", Value: bson.D{
				{Key: "name", Value: "$ownerData.name"},
				{Key: "id", Value: "$ownerData._id"},
			}},
		}}},
	}

	cursor, err := playlistsCol.Aggregate(ctx, pipeline)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search playlists"})
		return
	}
	defer cursor.Close(ctx)

	var results []bson.M
	cursor.All(ctx, &results) //nolint:errcheck
	if results == nil {
		results = []bson.M{}
	}

	c.JSON(http.StatusOK, gin.H{
		"playlists": results,
		"pagination": gin.H{
			"total": total,
			"page":  pg.PageNumber,
			"limit": pg.Limit,
			"pages": (total + pg.Limit - 1) / pg.Limit,
		},
	})
}
