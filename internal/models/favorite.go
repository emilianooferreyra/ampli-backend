package models

import "go.mongodb.org/mongo-driver/bson/primitive"

const FavoritesCollection = "favorites"

type Favorite struct {
	ID    primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Owner primitive.ObjectID   `bson:"owner" json:"owner"`
	Items []primitive.ObjectID `bson:"items" json:"items"`
}
