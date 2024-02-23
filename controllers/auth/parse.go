package auth

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lalathealter/medods/models"
)

func ParseTokenFromRequest(c *gin.Context, key string) (*jwt.Token, error) {
	token, err := c.Cookie(key)
	if err != nil {
		return nil, models.ErrNoRefreshTokenPassed
	}

	tokenObj, err := parseToken(token)
	if err != nil || !tokenObj.Valid {
		return nil, models.ErrTokenInvalid
	}

	return tokenObj, nil
}

func parseToken(tokenStr string) (*jwt.Token, error) {
	claims := jwt.RegisteredClaims{}
	tokenObj, err := jwt.ParseWithClaims(
		tokenStr, &claims, jwtParseKeyFunc,
	)

	return tokenObj, err
}

func jwtParseKeyFunc(t *jwt.Token) (interface{}, error) {
	_, ok := t.Method.(*jwt.SigningMethodHMAC)
	if !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
	}

	return retrieveSecret(), nil
}
