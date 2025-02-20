package grpctoken

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"

	"github.com/ZolaraProject/library/jwtToken"
	"github.com/ZolaraProject/library/logger"
	"google.golang.org/grpc/metadata"
)

var (
	grpcTokenAlphabet = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ23456789")
)

func generateGrpcToken() string {
	tk := make([]byte, 16)
	for i := range tk {
		tk[i] = grpcTokenAlphabet[rand.Intn(len(grpcTokenAlphabet))]
	}
	return string(tk)
}

func CreateContextFromHeader(r *http.Request, secretKey string) (context.Context, string) {
	grpcToken := generateGrpcToken()

	ctx := metadata.AppendToOutgoingContext(r.Context(), "zolara-grpc-token", grpcToken)

	zolaraUserId, err := jwtToken.GetUserIdFromToken(r, secretKey)
	if err != nil {
		logger.Err("", "Cannot get user id from claims: %s", err)
		return ctx, grpcToken
	}

	zolaraIsAdmin, err := jwtToken.GetUserIsAdminFromToken(r, secretKey)
	if err != nil {
		logger.Err("", "Cannot get user id from claims: %s", err)
		return ctx, grpcToken
	}

	ctx = metadata.AppendToOutgoingContext(ctx, "zolara-user-id", fmt.Sprintf("%d", int(zolaraUserId)))
	ctx = metadata.AppendToOutgoingContext(ctx, "zolara-is-admin", fmt.Sprintf("%t", zolaraIsAdmin))
	// ctx = metadata.AppendToOutgoingContext(ctx, "zolara-grpc-token", grpctoken)

	return ctx, grpcToken
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

// func GetJwtToken(ctx context.Context) string {
// 	md, ok := metadata.FromIncomingContext(ctx)
// 	if !ok {
// 		return "nil"
// 	}

// 	if len(md.Get("authorization")) == 0 {
// 		return "nil"
// 	}

// 	return md.Get("authorization")[0]
// }
