package jwtToken

import (
	"fmt"
	"net/http"
	"time"

	"github.com/ZolaraProject/library/logger"
	"github.com/golang-jwt/jwt/v5"
)

func CreateToken(userId int64, isAdmin bool, secretKey string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"userId": userId,
			"admin":  isAdmin,
			"exp":    time.Now().Add(time.Hour * 24).Unix(),
		},
	)

	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func SetTokenCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt",
		Value:    token,
		Expires:  time.Now().Add(time.Hour * 24),
		HttpOnly: false,
		SameSite: http.SameSiteNoneMode,
		Path:     "/",
		Secure:   true,
	})
}

func ValidateToken(tokenString string, secretKey []byte) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			logger.Err("", "unexpected signing method: %v", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return secretKey, nil
	})

	if err != nil {
		logger.Err("", "Error parsing token: %s", err)
		return nil, err
	}

	if !token.Valid {
		logger.Err("", "Invalid token: %s", err)
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

func GetTokanClaims(tokenString string, secretKey []byte) (*jwt.MapClaims, error) {
	token, err := ValidateToken(tokenString, secretKey)
	if err != nil {
		logger.Err("", "Error validating token: %s", err)
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		logger.Err("", "Error getting claims: %s", err)
		return nil, err
	}

	return &claims, nil
}

func GetUserIdFromToken(r *http.Request, secretKey string) (int64, error) {
	cookie, err := r.Cookie("jwt")
	if err != nil {
		logger.Err("", "Failed to get cookie: %s", err)
		return 0, fmt.Errorf("Unauthorized")
	}

	claims, err := GetTokanClaims(cookie.Value, []byte(secretKey))
	if err != nil {
		logger.Err("", "Error getting claims: %s", err)
		return 0, fmt.Errorf("Unauthorized")
	}

	id, ok := (*claims)["userId"].(float64)
	if !ok {
		logger.Err("", "Cannot get user id from claims: %s", err)
		return 0, fmt.Errorf("Cannot get user id from claims")
	}

	return int64(id), nil
}

func GetUserIsAdminFromToken(r *http.Request, secretKey string) (bool, error) {
	cookie, err := r.Cookie("jwt")
	if err != nil {
		logger.Err("", "Failed to get cookie: %s", err)
		return false, fmt.Errorf("Unauthorized")
	}

	claims, err := GetTokanClaims(cookie.Value, []byte(secretKey))
	if err != nil {
		logger.Err("", "Error getting claims: %s", err)
		return false, fmt.Errorf("Unauthorized")
	}

	isAdmin, ok := (*claims)["admin"].(bool)
	if !ok {
		logger.Err("", "Cannot get user id from claims: %s", err)
		return false, fmt.Errorf("Cannot get user id from claims")
	}

	return isAdmin, nil
}
