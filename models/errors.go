package models

import "errors"

var ErrEmptyConnectionString = errors.New("received an empty database connection string")

var ErrNoRefreshTokenPassed = errors.New("Found no refresh token in your request")

var ErrTokenInvalid = errors.New("Provided JWT token is invalid")

var ErrTokenOccupied = errors.New("Token for this GUID already exists;")
