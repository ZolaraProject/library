package grpctoken

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/ZolaraProject/library/logger"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc/metadata"
)

func DecodeJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT token")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	return string(payload), nil
}

func TransformJwtToGrpcToken(jwtPayload string) string {
	hash := sha256.New()
	hash.Write([]byte(jwtPayload))

	hashBytes := hash.Sum(nil)
	const base62Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	var result []byte
	decimalValue := new(big.Int).SetBytes(hashBytes)

	zero := new(big.Int)
	for decimalValue.Cmp(zero) > 0 {
		mod := new(big.Int)
		decimalValue.DivMod(decimalValue, big.NewInt(62), mod)
		result = append([]byte{base62Chars[mod.Int64()]}, result...)
	}

	grpcToken := string(result)

	if len(grpcToken) > 8 {
		grpcToken = grpcToken[:8]
	}

	return grpcToken
}

func CreateContextFromHeader(r *http.Request) (context.Context, string) {
	jwtToken, err := r.Cookie("jwt")
	if err != nil {
		return r.Context(), ""
	}

	token, err := jwt.Parse(jwtToken.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			logger.Err("", "unexpected signing method: %v", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(getEnv("JWT_SECRET")), nil
	})
	if err != nil {
		logger.Err("", "Error parsing token: %s", err)
		return r.Context(), ""
	}
	if !token.Valid {
		logger.Err("", "Invalid token: %s", err)
		return r.Context(), ""
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		logger.Err("", "Error getting claims: %s", err)
		return r.Context(), ""
	}

	zolaraUserId, ok := claims["userId"].(float64)
	if !ok {
		logger.Err("", "Cannot get user id from claims: %s", err)
		return r.Context(), ""
	}

	zolaraIsAdmin, ok := claims["admin"].(bool)
	if !ok {
		logger.Err("", "Cannot get user id from claims: %s", err)
		return r.Context(), ""
	}

	jwtPayload, err := DecodeJWT(jwtToken.Value)
	if err != nil {
		logger.Err("", "Error decoding JWT token: %s", err)
		return r.Context(), ""
	}

	grpctoken := TransformJwtToGrpcToken(jwtPayload)

	ctx := metadata.AppendToOutgoingContext(r.Context(), "zolara-user-id", fmt.Sprintf("%d", int(zolaraUserId)))
	ctx = metadata.AppendToOutgoingContext(ctx, "zolara-is-admin", fmt.Sprintf("%t", zolaraIsAdmin))
	ctx = metadata.AppendToOutgoingContext(ctx, "zolara-grpc-token", grpctoken)

	return ctx, grpctoken
}

func getEnv(key string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		log.Fatalf("'%s' environment variable isn't set\n", key)
	}
	return value
}

func GetToken(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "nil"
	}

	if len(md.Get("zolara-grpc-token")) == 0 {
		return "nil"
	}

	return md.Get("zolara-grpc-token")[0]
}

func GetJwtToken(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "nil"
	}

	if len(md.Get("authorization")) == 0 {
		return "nil"
	}

	return md.Get("authorization")[0]
}
