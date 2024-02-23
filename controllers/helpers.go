package controllers

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lalathealter/medods/controllers/auth"
	"github.com/lalathealter/medods/models"
)

func produceUniqueID(refreshToken *jwt.Token, guid string) (string, error) {
	t, err := refreshToken.Claims.GetIssuedAt()
	if err != nil {
		return "", models.ErrTokenInvalid
	}
	return fmt.Sprintf("%d -- %v", t.UnixMicro(), guid), nil
}


const JWT_ACCESS_TOKEN_KEY = "jwt_access_token"
const JWT_REFRESH_TOKEN_KEY = "jwt_refresh_token"
func sendBackTokenPair(c *gin.Context, pair *models.AuthTokenPair) {
  setSecureCookie(c, JWT_ACCESS_TOKEN_KEY, pair.AccessString, auth.ACCESS_TOKEN_LIFETIME)
  setSecureCookie(c, JWT_REFRESH_TOKEN_KEY, pair.RefreshString, auth.REFRESH_TOKEN_LIFETIME)
  c.JSON(http.StatusCreated, pair)
}

func setSecureCookie(c *gin.Context, key string, value string, duration time.Duration) {
  c.SetCookie(key, value, int(duration), "/", os.Getenv("host"), true, true)
}
