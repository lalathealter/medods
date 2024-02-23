package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lalathealter/medods/controllers/auth"
	"github.com/lalathealter/medods/models"
)

func (wr *WrapperAPI) RefreshAuthTokens(c *gin.Context) {
	accToken, err := auth.ParseTokenFromRequest(c, JWT_ACCESS_TOKEN_KEY)
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	guid, err := accToken.Claims.GetSubject()
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	refToken, err := auth.ParseTokenFromRequest(c, JWT_REFRESH_TOKEN_KEY)
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	unid, err := produceUniqueID(refToken, guid)
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	rightHash, err := wr.DB.GetRefreshTokenHash(unid)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	err = auth.VerifyRefreshToken(refToken, accToken, rightHash)
	if err != nil {
		c.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	pair, err := wr.reforgeRefreshToken(unid, guid)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	sendBackTokenPair(c, pair)
}


func (wr *WrapperAPI) reforgeRefreshToken(unid, guid string) (*models.AuthTokenPair, error) {
  err := wr.DB.DeleteRefreshTokenHash(unid)
  if err != nil {
    return nil, err
  }

  pair, err := auth.ForgeAuthPair(guid)
  if err != nil {
    return nil, err
  }

	err = wr.uploadRefreshToken(pair.RefreshObject, pair.RefreshString, guid)
  if err != nil {
    return nil, err
  }

  return pair, nil
}
