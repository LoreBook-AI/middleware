package middleware

import (
	"context"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte(os.Getenv("JWT_SECRET"))

type contextKey string

const userIDKey contextKey = "userID"

func ValidateAuthorization(w http.ResponseWriter, r *http.Request) (context.Context, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "missing auth header", http.StatusUnauthorized)
		return nil, false
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "invalid auth bearer", http.StatusUnauthorized)
		return nil, false
	}

	tokenStr := parts[1]
	claims := &jwt.MapClaims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return nil, false
	}

	ctx := context.WithValue(r.Context(), userIDKey, (*claims)["sub"])
	return ctx, true
}
