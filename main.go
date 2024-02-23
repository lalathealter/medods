package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/lalathealter/medods/controllers"
	"github.com/lalathealter/medods/models"
)



func main() {
  h := os.Getenv("host")
  p := os.Getenv("port")
  dbConnURL := os.Getenv("mongo_url")
  hp := net.JoinHostPort(h, p)

  db := models.InitWrapperDB(dbConnURL)
  defer func() {
    if err := db.Client.Disconnect(context.TODO()); err != nil {
      log.Panic(err)
    }
  }()

  api := controllers.InitWrapperAPI(db)
  g := setupGinRouter(api)

  fmt.Println("Listening on", hp)
  g.Run(hp)
}

func setupGinRouter(api *controllers.WrapperAPI) *gin.Engine {
  g := gin.Default()
  g.Use(controllers.FormatErrors)
  g.GET("/auth", api.GetAuthTokens)
  g.POST("/auth/refresh", api.RefreshAuthTokens)

  return g
}

