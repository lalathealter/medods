package models

import "github.com/golang-jwt/jwt/v5"

type AuthTokenPair struct {
	AccessString       string `json:"access_token"`
  AccessObject *jwt.Token `json:"-"`
	RefreshString      string `json:"refresh_token"`
  RefreshObject *jwt.Token `json:"-"`
}
