package security

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/ZolaraProject/library/grpctoken"
	"github.com/ZolaraProject/library/jwtToken"
	"github.com/ZolaraProject/library/logger"
	"github.com/mediocregopher/radix/v3"
	"google.golang.org/grpc/metadata"
)

type Response struct {
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
}

func PermissionCheck(handler func(http.ResponseWriter, *http.Request), requiredPermissions []string, secretKey string, redisPool *radix.Pool) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		permissionList, grpcToken, ok := ExtractPermissionList(r, secretKey, redisPool)
		logger.Debug(grpcToken, "Permission List: %v", permissionList)
		logger.Debug(grpcToken, "requiredPermissions: %v", requiredPermissions)

		if ok {
			for _, requiredPermission := range requiredPermissions {
				if !contains(permissionList, requiredPermission) {
					log.Printf("[%v] Access Denied (AND-CHECK). User-Permissions: '%v', Required-Permissions: '%v'.", grpcToken, permissionList, requiredPermissions)

					w.Header().Set("Content-Type", "application/json; charset=UTF-8")
					w.WriteHeader(http.StatusForbidden)
					res, _ := json.Marshal(Response{Message: "Permission denied", Token: grpcToken})
					w.Write(res)
					return
				}
			}
		}
		handler(w, r)
	}
}

func CheckJwtValidity(r *http.Request, ctx context.Context, grpcToken string, RedisPool *radix.Pool) (bool, error) {
	check, err := jwtToken.CheckTokenBlacklist(r, ctx, RedisPool)
	if err != nil {
		logger.Err(grpcToken, "failed to check token blacklist: %s", err)
		return false, err
	}

	return check, nil
}

func ExtractPermissionList(request *http.Request, secretKey string, redisPool *radix.Pool) ([]string, string, bool) {
	ctx, grpcToken := grpctoken.CreateContextFromHeader(request, secretKey)

	isValid, err := CheckJwtValidity(request, ctx, grpcToken, redisPool)
	logger.Debug(grpcToken, "Token validity: %v", isValid)
	if err != nil {
		logger.Err(grpcToken, "Failed to check jwt validity: %s", err)
		return []string{}, "", false
	}
	if !isValid {
		logger.Err(grpcToken, "Token is blacklisted")
		return []string{}, "", false
	}

	var permissionList []string
	var isUser bool

	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		logger.Err(grpcToken, "Failed to retrieve metadata from context")
		return []string{}, "", false
	}

	userId := md.Get("zolara-user-id")
	if len(userId) > 0 {
		isUser = true
	}
	if isUser {
		permissionList = append(permissionList, "USER")
	}

	isAdm := md.Get("zolara-is-admin")
	if isAdm != nil {
		isAdmin, err := strconv.ParseBool(isAdm[0])
		if err != nil {
			return []string{}, "", false
		}
		if isAdmin {
			permissionList = append(permissionList, "ADMIN")
		}
	}

	return permissionList, grpcToken, true
}

func contains(slice []string, value string) bool {
	for _, element := range slice {
		if element == value {
			return true
		}
	}
	return false
}
