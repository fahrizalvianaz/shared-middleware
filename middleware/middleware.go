package middleware

import (
	"net/http"
	"strings"

	configs "github.com/fahrizalvianaz/shared-configuration/configs"
	shared_middleware "github.com/fahrizalvianaz/shared-middleware"
	genericResponse "github.com/fahrizalvianaz/shared-response/httputil"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func JWTAuth() gin.HandlerFunc {
	cfg, err := configs.LoadConfig()
	if err != nil {
		panic("error when load config")
	}
	return func(ctx *gin.Context) {
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			genericResponse.UnauthorizedResponse(ctx)
			ctx.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			genericResponse.ErrorResponse(ctx, http.StatusUnauthorized, "invalid authorization format", nil)
			ctx.Abort()
			return
		}

		tokenString := parts[1]

		token, err := jwt.ParseWithClaims(
			tokenString,
			&shared_middleware.Claims{},
			func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return []byte(cfg.SecretKey), nil
			},
		)

		if err != nil {
			genericResponse.ErrorResponse(ctx, http.StatusUnauthorized, "invalid or expired token", err.Error())
			ctx.Abort()
			return
		}

		if claims, ok := token.Claims.(*shared_middleware.Claims); ok && token.Valid {
			ctx.Set("userID", claims.UserID)
			ctx.Set("username", claims.Username)
			ctx.Set("email", claims.Email)
			ctx.Next()
		} else {
			genericResponse.UnauthorizedResponse(ctx)
			ctx.Abort()
			return
		}
	}
}
