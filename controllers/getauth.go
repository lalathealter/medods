package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lalathealter/medods/controllers/auth"
	"github.com/lalathealter/medods/models"
)


func (wr *WrapperAPI) GetAuthTokens(c *gin.Context) {
	at := &models.AuthTarget{}

	err := c.ShouldBind(at)
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, models.ErrReceivedNoGUID)
		return
	}

	err = at.PutInOrderGUID()
	if err != nil || !at.HasValidGUID() {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	tokenPair, err := auth.ForgeAuthPair(at.GUID)
  if err != nil {
    c.AbortWithError(http.StatusInternalServerError, err)
    return
  }
    

  err = wr.uploadRefreshToken(tokenPair.RefreshObject, tokenPair.RefreshString, at.GUID)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	sendBackTokenPair(c, tokenPair)
}
