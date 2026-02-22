package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const HistoriesCollection = "histories"

type HistoryItem struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Audio    primitive.ObjectID `bson:"audio" json:"audio"`
	Progress float64            `bson:"progress" json:"progress"`
	Date     time.Time          `bson:"date" json:"date"`
}

type History struct {
	ID    primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Owner primitive.ObjectID `bson:"owner" json:"owner"`
	Last  *HistoryItem       `bson:"last,omitempty" json:"last,omitempty"`
	All   []HistoryItem      `bson:"all" json:"all"`
}
