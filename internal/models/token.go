package models

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strconv"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

const (
	EmailVerificationTokensCollection = "emailverificationtokens"
	PasswordResetTokensCollection     = "passwordresettokens"
)

type EmailVerificationToken struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	Owner     primitive.ObjectID `bson:"owner"`
	Token     string             `bson:"token"` // stored as bcrypt hash
	CreatedAt time.Time          `bson:"createdAt"`
}

type PasswordResetToken struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	Owner     primitive.ObjectID `bson:"owner"`
	Token     string             `bson:"token"` // stored as bcrypt hash
	CreatedAt time.Time          `bson:"createdAt"`
}

// GenerateToken generates a random hex token (e.g. for email verification).
// Returns (plaintext, bcryptHash, error).
func GenerateToken(byteLen int) (plain string, hashed string, err error) {
	b := make([]byte, byteLen)
	if _, err = rand.Read(b); err != nil {
		return
	}
	plain = hex.EncodeToString(b)

	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	hashed = string(h)
	return
}

// GenerateOTP generates a 6-digit numeric OTP.
// Returns (plaintext, bcryptHash, error).
func GenerateOTP() (plain string, hashed string, err error) {
	var otp string
	for i := 0; i < 6; i++ {
		n, e := rand.Int(rand.Reader, big.NewInt(10))
		if e != nil {
			err = e
			return
		}
		otp += strconv.Itoa(int(n.Int64()))
	}
	plain = otp

	h, e := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if e != nil {
		err = e
		return
	}
	hashed = string(h)
	return
}

// CompareToken checks a plaintext token against a bcrypt hash.
func CompareToken(plain, hashed string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain)) == nil
}

// HashPassword hashes a password using bcrypt.
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(h), err
}

// ComparePassword checks a plaintext password against a bcrypt hash.
func ComparePassword(plain, hashed string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain)) == nil
}
