package pkg

import (
	"bookstore-framework/configs"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTGenerator interface {
	GenerateToken(userId uint, username, email string) (string, error)
}

type Claims struct {
	UserID   uint   `json:"userID"`
	Username string `json:"username"`
	Email    string `json:"email"`
	jwt.RegisteredClaims
}

func (c *Claims) GenerateToken(userId uint, username, email string) (string, error) {
	cfg, err := configs.LoadConfig()
	if err != nil {
		return "", err
	}
	claims := Claims{
		UserID:   userId,
		Username: username,
		Email:    email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Subject:   username,
			Audience:  jwt.ClaimStrings{cfg.TokenAudience},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(cfg.SecretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
