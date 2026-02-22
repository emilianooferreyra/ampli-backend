package db

import (
	"context"
	"log/slog"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func Connect(uri string) *mongo.Database {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		slog.Error("failed to connect to MongoDB", "err", err)
		panic(err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		slog.Error("failed to ping MongoDB", "err", err)
		panic(err)
	}

	slog.Info("connected to MongoDB")
	return client.Database("intune")
}

func Disconnect(database *mongo.Database) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := database.Client().Disconnect(ctx); err != nil {
		slog.Error("error disconnecting from MongoDB", "err", err)
	}
	slog.Info("disconnected from MongoDB")
}
