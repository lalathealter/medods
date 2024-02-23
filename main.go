package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

func init() {
  err := godotenv.Load()
  if err != nil {
    fmt.Println("failed to load a .env file; Going to load environmental variables directly from OS")
  }

  retrieveSecret = bindSecret()
}

var retrieveSecret func()[]byte 
func bindSecret()func()[]byte {
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



func main() {
  h := os.Getenv("host")
  p := os.Getenv("port")
  hp := net.JoinHostPort(h, p)

  db := InitWrapperDB(TokensMap{})
  api := InitWrapperAPI(db)
  g := setupGinRouter(api)

  fmt.Println("Listening on", hp)
  g.Run(hp)
}

func setupGinRouter(api *WrapperAPI) *gin.Engine {
  g := gin.Default()
  g.Use(FormatErrors)
  g.GET("/auth", api.GetAuthTokens)
  g.POST("/auth/refresh", api.RefreshAuthTokens)

  return g
}

func FormatErrors(c *gin.Context) {
  c.Next()

  if len(c.Errors) >= 1  {
    foundError := c.Errors[len(c.Errors)-1]
    c.JSON(-1, foundError)
  }
}

type WrapperAPI struct {
  DB DBI
}

type DBI interface {
  UploadRefreshToken(*jwt.Token, []byte, string) error
  CheckRefreshToken(*jwt.Token, *jwt.Token, string) error
  DeleteRefreshToken(string) error
}

type TokensMap map[string][]byte

type WrapperDB struct {
  Tokens TokensMap
}

func InitWrapperDB(db TokensMap) *WrapperDB {
  return &WrapperDB{db}
}


var ErrTokenOccupied = errors.New("Token for this GUID already exists;")
func (wdb *WrapperDB) UploadRefreshToken(refreshToken *jwt.Token, refSign []byte, guid string) error {
  unID, err := produceUniqueID(refreshToken, guid)
  if err != nil {
    return err
  }

  _, ok := wdb.Tokens[unID]
  if ok {
    return ErrTokenOccupied
  }

  crypted, err := bcrypt.GenerateFromPassword(refSign, bcrypt.DefaultCost)
  if err != nil {
    return err
  }
  
  wdb.Tokens[unID] = crypted
  defer wdb.scheduleDeletingToken(unID, REFRESH_TOKEN_LIFETIME)
  return nil
}

func produceUniqueID(refreshToken *jwt.Token, guid string) (string, error) {
  t, err := refreshToken.Claims.GetIssuedAt()
  if err != nil {
    return "", ErrTokenInvalid
  }
  return fmt.Sprintf("%d -- %v", t.UnixMicro(), guid), nil
}

func (wdb *WrapperDB) scheduleDeletingToken(unidKey string, duration time.Duration) {
  go func() {
    time.Sleep(duration)
    wdb.DeleteRefreshToken(unidKey)
  }()
}


func (wdb *WrapperDB) DeleteRefreshToken(unid string) error {
  delete(wdb.Tokens, unid)
  return nil
}

func (wdb *WrapperDB) CheckRefreshToken(refToken *jwt.Token, accToken *jwt.Token, guid string) error {
  reffedAccessSignature, err := refToken.Claims.GetSubject()
  if err != nil {
    return ErrTokenInvalid
  }

  if reffedAccessSignature != takeSignature(accToken.Raw) {
    return ErrTokenInvalid
  }

  unid, err := produceUniqueID(refToken, guid)
  if err != nil {
    return err
  }

  rightHash, ok := wdb.Tokens[unid]
  if !ok {
    return ErrTokenInvalid
  }

  sign := takeSignature(refToken.Raw)
  refToken.Claims.GetSubject()
  err = bcrypt.CompareHashAndPassword(rightHash, []byte(sign))
  if err != nil {
    return ErrTokenInvalid
  }

  return nil
}


func InitWrapperAPI(db DBI) *WrapperAPI {
  return &WrapperAPI{db}
}

type AuthTarget struct {
  GUID string `form:"guid" binding:"required"`
}

func (at *AuthTarget) PutInOrderGUID() error {
  id := at.GUID
  if id == "" {
    return ErrReceivedNoGUID
  }

  id = strings.Trim(id, " ")
  if id[0] == '{' {
    // cutting off curly braces (if any)
    id = id[1:len(id)-1]
  }

  // one case for all hex nums
  id = strings.ToUpper(id)

  // getting the dashes out (if any)
  sections := strings.Split(id, "-")
  if len(sections) == 5 {
    at.GUID = strings.Join(sections, "")
  } else if len(sections) != 1 {
    return ErrReceivedNoGUID
  }
  return nil
}

func (at *AuthTarget) HasValidGUID() bool {
  if len(at.GUID) != 32 {
    return false
  }

  _, err := hex.DecodeString(at.GUID)
  return err == nil
}

var ErrReceivedNoGUID = errors.New("No appropriate GUID passed in query parameters;")
func (wr *WrapperAPI) GetAuthTokens(c *gin.Context) {
  at := &AuthTarget{}

  err := c.ShouldBind(at)
  if err != nil {
    c.AbortWithError(http.StatusBadRequest, ErrReceivedNoGUID)
    return
  }

  err = at.PutInOrderGUID()
  if err != nil || !at.HasValidGUID() {
    c.AbortWithError(http.StatusBadRequest, ErrReceivedNoGUID)
    return
  }

  tokenPair, err := wr.forgeAuthPair(at.GUID)
  if err != nil {
    c.AbortWithError(http.StatusInternalServerError, err)
    return
  }


  sendBackTokenPair(c, tokenPair)
}

type AuthTokenPair struct {
  Access string `json:"access_token"`
  Refresh string `json:"refresh_token"`
}

const (
  ACCESS_TOKEN_LIFETIME = time.Minute * 30
  REFRESH_TOKEN_LIFETIME = time.Minute * 120
)

func (wr *WrapperAPI) forgeAuthPair(guid string) (*AuthTokenPair, error) {
  pair := &AuthTokenPair{}
  accToken := forgeAccessToken(guid, ACCESS_TOKEN_LIFETIME)
  accTokenSigned, err := accToken.SignedString(retrieveSecret())
  if err != nil {
    return nil, err
  }

  accSignature := takeSignature(accTokenSigned)
  refToken := forgeRefreshToken(accSignature, REFRESH_TOKEN_LIFETIME)
  refTokenSigned, err := refToken.SignedString(retrieveSecret())
  if err != nil {
    return nil, err
  }  

  pair.Access = accTokenSigned
  pair.Refresh = refTokenSigned

  refSignature := takeSignature(refTokenSigned)
  err = wr.DB.UploadRefreshToken(refToken, []byte(refSignature), guid)
  return pair, nil
}

func takeSignature(jwtStr string) string {
  res := strings.Split(jwtStr, ".")[2]
  return res
}

func forgeRefreshToken(subject string, duration time.Duration) *jwt.Token {
  now := time.Now()
  claims := jwt.RegisteredClaims{
    Subject: subject,
    IssuedAt: jwt.NewNumericDate(now),
    ExpiresAt: jwt.NewNumericDate(produceExpirationTime(now, duration)),
  }
  t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

  return t
}

func forgeAccessToken(subject string, duration time.Duration) (*jwt.Token) {
  now := time.Now()
  claims := jwt.RegisteredClaims{
    Subject: subject,
    ExpiresAt: jwt.NewNumericDate(produceExpirationTime(now, duration)),
  }
  t := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
  
  return t
}

func produceExpirationTime(now time.Time, duration time.Duration) (time.Time) {
  res := now.Add(duration)
  return res
}

func parseTokenFromRequest(c *gin.Context, key string) (*jwt.Token, error) {
  token, err := c.Cookie(key)
  if err != nil {
    return nil, ErrNoRefreshTokenPassed
  }

  tokenObj, err := parseToken(token)
  if err != nil || !tokenObj.Valid {
    return nil, ErrTokenInvalid
  }

  return tokenObj, nil
}

var ErrNoRefreshTokenPassed = errors.New("Found no refresh token in your request")
func (wr *WrapperAPI) RefreshAuthTokens(c *gin.Context) {
  accToken, err := parseTokenFromRequest(c, JWT_ACCESS_TOKEN_KEY)
  if err != nil {
    c.AbortWithError(http.StatusBadRequest, err)
    return
  }

  guid, err := accToken.Claims.GetSubject()
  if err != nil {
    c.AbortWithError(http.StatusBadRequest, err)
    return 
  }
 
  refToken, err := parseTokenFromRequest(c, JWT_REFRESH_TOKEN_KEY)
  if err != nil {
    c.AbortWithError(http.StatusBadRequest, err)
    return
  }

  err = wr.DB.CheckRefreshToken(refToken, accToken, guid)
  if err != nil {
    c.AbortWithError(http.StatusUnauthorized, err)
    return
  }
  unid, err := produceUniqueID(refToken, guid)

  err = wr.DB.DeleteRefreshToken(unid)
  if err != nil {
    c.AbortWithError(http.StatusInternalServerError, err)
    return
  }

  pair, err := wr.forgeAuthPair(guid)
  if err != nil {
    c.AbortWithError(http.StatusInternalServerError, err)
    return
  }

  sendBackTokenPair(c, pair)
}


const JWT_ACCESS_TOKEN_KEY = "jwt_access_token"
const JWT_REFRESH_TOKEN_KEY = "jwt_refresh_token"
func sendBackTokenPair(c *gin.Context, pair *AuthTokenPair) {
  setSecureCookie(c, JWT_ACCESS_TOKEN_KEY, pair.Access, ACCESS_TOKEN_LIFETIME)
  setSecureCookie(c, JWT_REFRESH_TOKEN_KEY, pair.Refresh, REFRESH_TOKEN_LIFETIME)
  c.JSON(http.StatusCreated, pair)
}

func setSecureCookie(c *gin.Context, key string, value string, duration time.Duration) {
  c.SetCookie(key, value, int(duration), "/", os.Getenv("host"), true, true)
}


var ErrTokenInvalid = errors.New("Provided JWT token is invalid")


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
