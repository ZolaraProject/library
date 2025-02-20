package security

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/ZolaraProject/library/grpctoken"
	"github.com/ZolaraProject/library/logger"
)

type Response struct {
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
}

func PermissionCheck(handler func(http.ResponseWriter, *http.Request), requiredPermissions []string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		permissionList, grpcToken, ok := ExtractPermissionList(r)
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

func ExtractPermissionList(request *http.Request) ([]string, string, bool) {
	ctx, grpcToken := grpctoken.CreateContextFromHeader(request)

	var permissionList []string
	var isUser bool
	userId := ctx.Value("zolara-user-id")
	if userId != nil {
		isUser = true
	}
	if isUser {
		permissionList = append(permissionList, "USER")
	}

	isAdm := ctx.Value("zolara-is-admin")
	if isAdm != nil {
		isAdmin, err := strconv.ParseBool(isAdm.(string))
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
