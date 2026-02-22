package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const UsersCollection = "users"

type Avatar struct {
	URL      string `bson:"url" json:"url"`
	PublicID string `bson:"publicId" json:"publicId"`
}

// User is the MongoDB document struct.
type User struct {
	ID         primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Name       string               `bson:"name" json:"name"`
	Email      string               `bson:"email" json:"email"`
	Password   string               `bson:"password" json:"-"`
	Verified   bool                 `bson:"verified" json:"verified"`
	Avatar     *Avatar              `bson:"avatar,omitempty" json:"avatar,omitempty"`
	Tokens     []string             `bson:"tokens" json:"-"`
	Favorites  []primitive.ObjectID `bson:"favorites" json:"favorites"`
	Followers  []primitive.ObjectID `bson:"followers" json:"followers"`
	Followings []primitive.ObjectID `bson:"followings" json:"followings"`
	CreatedAt  time.Time            `bson:"createdAt" json:"createdAt"`
	UpdatedAt  time.Time            `bson:"updatedAt" json:"updatedAt"`
}

// UserProfile is the safe DTO returned to clients.
type UserProfile struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Verified   bool   `json:"verified"`
	Avatar     string `json:"avatar,omitempty"`
	Followers  int    `json:"followers"`
	Followings int    `json:"followings"`
}

func (u *User) ToProfile() UserProfile {
	p := UserProfile{
		ID:         u.ID.Hex(),
		Name:       u.Name,
		Email:      u.Email,
		Verified:   u.Verified,
		Followers:  len(u.Followers),
		Followings: len(u.Followings),
	}
	if u.Avatar != nil {
		p.Avatar = u.Avatar.URL
	}
	return p
}
