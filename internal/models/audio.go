package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const AudiosCollection = "audios"

var AudioCategories = []string{
	"Arts", "Business", "Education", "Entertainment", "Kids & Family",
	"Music", "News", "Science", "Sports", "Technology", "Travel", "Others",
}

type AudioFile struct {
	URL      string `bson:"url" json:"url"`
	PublicID string `bson:"publicId" json:"publicId"`
}

type Audio struct {
	ID        primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Title     string               `bson:"title" json:"title"`
	About     string               `bson:"about" json:"about"`
	Owner     primitive.ObjectID   `bson:"owner" json:"owner"`
	File      AudioFile            `bson:"file" json:"file"`
	Poster    *AudioFile           `bson:"poster,omitempty" json:"poster,omitempty"`
	Likes     []primitive.ObjectID `bson:"likes" json:"likes"`
	Category  string               `bson:"category" json:"category"`
	CreatedAt time.Time            `bson:"createdAt" json:"createdAt"`
	UpdatedAt time.Time            `bson:"updatedAt" json:"updatedAt"`
}
