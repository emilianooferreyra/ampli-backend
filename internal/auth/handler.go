package auth

import (
	"context"
	"net/http"
	"time"

	"ampli/api/internal/cloud"
	"ampli/api/internal/config"
	"ampli/api/internal/mail"
	"ampli/api/internal/middleware"
	"ampli/api/internal/models"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Handler contains all auth-related route handlers.
type Handler struct {
	db     *mongo.Database
	cloud  *cloud.Client
	mailer *mail.Mailer
	cfg    *config.Config
}

func NewHandler(db *mongo.Database, cloud *cloud.Client, mailer *mail.Mailer, cfg *config.Config) *Handler {
	return &Handler{db: db, cloud: cloud, mailer: mailer, cfg: cfg}
}

// RegisterRoutes wires all /auth routes to the Gin engine.
// Mirrors the Express auth router.
func (h *Handler) RegisterRoutes(r *gin.Engine, auth *middleware.Auth) {
	g := r.Group("/auth")

	g.POST("/create", middleware.AuthRateLimit(), h.Create)
	g.POST("/verify-email", h.VerifyEmail)
	g.POST("/re-verify-email", h.SendReVerificationToken)
	g.POST("/forget-password", middleware.PasswordResetRateLimit(), h.GenerateForgetPasswordLink)
	g.POST("/verify-pass-reset-token", h.VerifyPassResetToken)
	g.POST("/update-password", middleware.PasswordResetRateLimit(), h.UpdatePassword)
	g.POST("/sign-in", middleware.AuthRateLimit(), h.SignIn)
	g.GET("/is-auth", auth.RequireAuth(), h.SendProfile)
	g.POST("/update-profile", auth.RequireAuth(), h.UpdateProfile)
	g.POST("/log-out", auth.RequireAuth(), h.LogOut)
}

// --- Request structs (replaces Zod schemas) ---

type createUserReq struct {
	Name     string `json:"name" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type verifyEmailReq struct {
	Token  string `json:"token" binding:"required"`
	UserID string `json:"userId" binding:"required"`
}

type reVerifyEmailReq struct {
	UserID string `json:"userId" binding:"required"`
}

type forgetPasswordReq struct {
	Email string `json:"email" binding:"required,email"`
}

type updatePasswordReq struct {
	Password string `json:"password" binding:"required,min=8"`
	UserID   string `json:"userId" binding:"required"`
	Token    string `json:"token" binding:"required"`
}

type signInReq struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// --- Handlers ---

// Create registers a new user.
// POST /auth/create
func (h *Handler) Create(c *gin.Context) {
	var req createUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	users := h.db.Collection(models.UsersCollection)

	// Check duplicate email
	count, err := users.CountDocuments(ctx, bson.M{"email": req.Email})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "Email is already in use!"})
		return
	}

	hashedPwd, err := models.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	user := models.User{
		ID:         primitive.NewObjectID(),
		Name:       req.Name,
		Email:      req.Email,
		Password:   hashedPwd,
		Verified:   false,
		Tokens:     []string{},
		Favorites:  []primitive.ObjectID{},
		Followers:  []primitive.ObjectID{},
		Followings: []primitive.ObjectID{},
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if _, err := users.InsertOne(ctx, user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Generate + store email verification token
	plain, hashed, err := models.GenerateToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	evToken := models.EmailVerificationToken{
		ID:        primitive.NewObjectID(),
		Owner:     user.ID,
		Token:     hashed,
		CreatedAt: time.Now(),
	}
	h.db.Collection(models.EmailVerificationTokensCollection).InsertOne(ctx, evToken) //nolint:errcheck

	// Send verification email (non-blocking fail)
	go h.mailer.SendVerificationEmail(req.Email, req.Name, plain, user.ID.Hex()) //nolint:errcheck

	c.JSON(http.StatusCreated, gin.H{
		"user": gin.H{"id": user.ID.Hex(), "name": user.Name, "email": user.Email},
	})
}

// VerifyEmail verifies a user's email via token.
// POST /auth/verify-email
func (h *Handler) VerifyEmail(c *gin.Context) {
	var req verifyEmailReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, err := primitive.ObjectIDFromHex(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user id!"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	evTokens := h.db.Collection(models.EmailVerificationTokensCollection)
	users := h.db.Collection(models.UsersCollection)

	var evToken models.EmailVerificationToken
	if err := evTokens.FindOne(ctx, bson.M{"owner": userID}).Decode(&evToken); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invalid token!"})
		return
	}

	if !models.CompareToken(req.Token, evToken.Token) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invalid token!"})
		return
	}

	users.UpdateOne(ctx, bson.M{"_id": userID}, bson.M{"$set": bson.M{"verified": true, "updatedAt": time.Now()}}) //nolint:errcheck
	evTokens.DeleteOne(ctx, bson.M{"_id": evToken.ID})                                                             //nolint:errcheck

	c.JSON(http.StatusOK, gin.H{"message": "Your email is verified."})
}

// SendReVerificationToken re-sends the email verification token.
// POST /auth/re-verify-email
func (h *Handler) SendReVerificationToken(c *gin.Context) {
	var req reVerifyEmailReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, err := primitive.ObjectIDFromHex(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user id!"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var user models.User
	if err := h.db.Collection(models.UsersCollection).FindOne(ctx, bson.M{"_id": userID}).Decode(&user); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found!"})
		return
	}

	if user.Verified {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Your account is already verified!"})
		return
	}

	evTokens := h.db.Collection(models.EmailVerificationTokensCollection)
	evTokens.DeleteOne(ctx, bson.M{"owner": userID}) //nolint:errcheck

	plain, hashed, err := models.GenerateToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	evTokens.InsertOne(ctx, models.EmailVerificationToken{ //nolint:errcheck
		ID: primitive.NewObjectID(), Owner: userID, Token: hashed, CreatedAt: time.Now(),
	})

	go h.mailer.SendVerificationEmail(user.Email, user.Name, plain, user.ID.Hex()) //nolint:errcheck

	c.JSON(http.StatusOK, gin.H{"message": "Please check your mail."})
}

// GenerateForgetPasswordLink sends a password reset link.
// POST /auth/forget-password
func (h *Handler) GenerateForgetPasswordLink(c *gin.Context) {
	var req forgetPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Always respond with the same message (security: don't reveal if email exists)
	msg := "If an account exists with this email, a password reset link has been sent."

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var user models.User
	err := h.db.Collection(models.UsersCollection).FindOne(ctx, bson.M{"email": req.Email}).Decode(&user)
	if err != nil || !user.Verified {
		c.JSON(http.StatusOK, gin.H{"message": msg})
		return
	}

	prTokens := h.db.Collection(models.PasswordResetTokensCollection)
	prTokens.DeleteOne(ctx, bson.M{"owner": user.ID}) //nolint:errcheck

	plain, hashed, err := models.GenerateToken(36)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": msg})
		return
	}

	prTokens.InsertOne(ctx, models.PasswordResetToken{ //nolint:errcheck
		ID: primitive.NewObjectID(), Owner: user.ID, Token: hashed, CreatedAt: time.Now(),
	})

	resetLink := h.cfg.PasswordResetLink + "?token=" + plain + "&userId=" + user.ID.Hex()
	go h.mailer.SendForgetPasswordLink(user.Email, resetLink) //nolint:errcheck

	c.JSON(http.StatusOK, gin.H{"message": msg})
}

// VerifyPassResetToken validates a password reset token.
// POST /auth/verify-pass-reset-token
func (h *Handler) VerifyPassResetToken(c *gin.Context) {
	var req verifyEmailReq // same shape: token + userId
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.validatePassResetToken(c.Request.Context(), req.Token, req.UserID); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "Unauthorized access, invalid token!"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"valid": true})
}

// UpdatePassword sets a new password after reset token validation.
// POST /auth/update-password
func (h *Handler) UpdatePassword(c *gin.Context) {
	var req updatePasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.validatePassResetToken(c.Request.Context(), req.Token, req.UserID); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "Unauthorized access, invalid token!"})
		return
	}

	userID, _ := primitive.ObjectIDFromHex(req.UserID)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var user models.User
	if err := h.db.Collection(models.UsersCollection).FindOne(ctx, bson.M{"_id": userID}).Decode(&user); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "Unauthorized access!"})
		return
	}

	if models.ComparePassword(req.Password, user.Password) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "The new password must be different!"})
		return
	}

	hashed, err := models.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	h.db.Collection(models.UsersCollection).UpdateOne(ctx, //nolint:errcheck
		bson.M{"_id": userID},
		bson.M{"$set": bson.M{"password": hashed, "updatedAt": time.Now()}},
	)
	h.db.Collection(models.PasswordResetTokensCollection).DeleteOne(ctx, bson.M{"owner": userID}) //nolint:errcheck

	go h.mailer.SendPasswordResetSuccess(user.Email, user.Name) //nolint:errcheck

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully."})
}

// SignIn authenticates a user and returns a JWT.
// POST /auth/sign-in
func (h *Handler) SignIn(c *gin.Context) {
	var req signInReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	users := h.db.Collection(models.UsersCollection)

	var user models.User
	if err := users.FindOne(ctx, bson.M{"email": req.Email}).Decode(&user); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "Email/Password mismatch!"})
		return
	}

	if !models.ComparePassword(req.Password, user.Password) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Email/Password mismatch!"})
		return
	}

	token, err := middleware.SignToken(user.ID, h.cfg.JWTSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Keep max 5 tokens (LIFO, drop oldest)
	tokens := append(user.Tokens, token)
	if len(tokens) > 5 {
		tokens = tokens[len(tokens)-5:]
	}

	users.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{ //nolint:errcheck
		"$set": bson.M{"tokens": tokens, "updatedAt": time.Now()},
	})

	c.JSON(http.StatusOK, gin.H{
		"profile": user.ToProfile(),
		"token":   token,
	})
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

		// Delete old avatar if exists
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

	// Return updated profile
	users.FindOne(ctx, bson.M{"_id": userID}).Decode(&user) //nolint:errcheck
	c.JSON(http.StatusOK, gin.H{"profile": user.ToProfile()})
}

// LogOut removes the current (or all) token(s).
// POST /auth/log-out
func (h *Handler) LogOut(c *gin.Context) {
	profile := middleware.GetUser(c)
	token := middleware.GetToken(c)
	fromAll := c.Query("fromAll") == "yes"

	userID, _ := primitive.ObjectIDFromHex(profile.ID)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	var update bson.M
	if fromAll {
		update = bson.M{"$set": bson.M{"tokens": []string{}, "updatedAt": time.Now()}}
	} else {
		update = bson.M{"$pull": bson.M{"tokens": token}, "$set": bson.M{"updatedAt": time.Now()}}
	}

	h.db.Collection(models.UsersCollection).UpdateOne(ctx, bson.M{"_id": userID}, update) //nolint:errcheck

	msg := "Logged out successfully"
	if fromAll {
		msg = "Logged out from all devices"
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": msg})
}

// --- Private helpers ---

func (h *Handler) validatePassResetToken(ctx context.Context, tokenPlain, userIDStr string) error {
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var prToken models.PasswordResetToken
	err = h.db.Collection(models.PasswordResetTokensCollection).
		FindOne(ctx, bson.M{"owner": userID}).
		Decode(&prToken)
	if err != nil {
		return err
	}

	if !models.CompareToken(tokenPlain, prToken.Token) {
		return mongo.ErrNoDocuments
	}
	return nil
}

// ensureIndex is a helper used at startup to create MongoDB indexes.
func EnsureIndexes(ctx context.Context, db *mongo.Database) {
	db.Collection(models.UsersCollection).Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "name", Value: "text"}}},
	}) //nolint:errcheck

	db.Collection(models.AudiosCollection).Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "title", Value: "text"}, {Key: "about", Value: "text"}}},
		{Keys: bson.D{{Key: "category", Value: 1}, {Key: "createdAt", Value: -1}}},
		{Keys: bson.D{{Key: "owner", Value: 1}, {Key: "createdAt", Value: -1}}},
	}) //nolint:errcheck

	// TTL index: email verification tokens expire after 1 hour
	db.Collection(models.EmailVerificationTokensCollection).Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "createdAt", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(3600),
	}) //nolint:errcheck

	// TTL index: password reset tokens expire after 1 hour
	db.Collection(models.PasswordResetTokensCollection).Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "createdAt", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(3600),
	}) //nolint:errcheck
}
