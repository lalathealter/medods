package auth

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/lalathealter/medods/models"
	"golang.org/x/crypto/bcrypt"
)

const (
	ACCESS_TOKEN_LIFETIME  = time.Minute * 30
	REFRESH_TOKEN_LIFETIME = time.Minute * 120
)

func init() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("failed to load a .env file; Going to load environmental variables directly from OS")
	}

	retrieveSecret = bindSecret()
}

var retrieveSecret func() []byte

func bindSecret() func() []byte {
	secretStr := os.Getenv("MEDODS_JWT_SECRET")
	var secret []byte = []byte(secretStr)

	if len(secretStr) == 0 {
		secret = generateSecret(36)
		fmt.Println("Found no secret in the environment; Using a freshly generated one")
	}

	return func() []byte {
		return secret
	}
}

func generateSecret(size int) []byte {
	if size < 0 {
		size = -size
	}
	sc := make([]byte, size)
	rand.Read(sc)
	return sc
}

func TakeSignature(jwtStr string) string {
	res := strings.Split(jwtStr, ".")[2]
	return res
}

func forgeRefreshToken(subject string, duration time.Duration) *jwt.Token {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Subject:   subject,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return t
}

func forgeAccessToken(subject string, duration time.Duration) *jwt.Token {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Subject:   subject,
		ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	return t
}

func ForgeAuthPair(guid string) (*models.AuthTokenPair, error) {
	accToken := forgeAccessToken(guid, ACCESS_TOKEN_LIFETIME)
	accTokenSigned, err := accToken.SignedString(retrieveSecret())
	if err != nil {
		return nil, err
	}

	accSignature := TakeSignature(accTokenSigned)
	refToken := forgeRefreshToken(accSignature, REFRESH_TOKEN_LIFETIME)
	refTokenSigned, err := refToken.SignedString(retrieveSecret())
	if err != nil {
		return nil, err
	}

	pair := &models.AuthTokenPair{
    AccessObject: accToken,
    AccessString: accTokenSigned,
    RefreshObject: refToken,
    RefreshString: refTokenSigned,
  }

  return pair, err
}

func ProduceBcrypt(tokenStr string) ([]byte, error) {
  refSign := []byte(TakeSignature(tokenStr))
	return bcrypt.GenerateFromPassword(refSign, bcrypt.DefaultCost)
}


func VerifyRefreshToken(refToken *jwt.Token, accToken *jwt.Token, rightHash []byte) error {
  reffedAccessSignature, err := refToken.Claims.GetSubject()
  if err != nil {
    return models.ErrTokenInvalid
  }

  if reffedAccessSignature != TakeSignature(accToken.Raw) {
    return models.ErrTokenInvalid
  }

  sign := TakeSignature(refToken.Raw)
  err = bcrypt.CompareHashAndPassword(rightHash, []byte(sign))
  if err != nil {
    return models.ErrTokenInvalid
  }
  return nil
}


