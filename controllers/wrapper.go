package controllers

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lalathealter/medods/controllers/auth"
	"github.com/lalathealter/medods/models"
)


type WrapperAPI struct {
	DB models.DBI
}

func InitWrapperAPI(db models.DBI) *WrapperAPI {
	return &WrapperAPI{db}
}

func (wr *WrapperAPI) uploadRefreshToken(refreshToken *jwt.Token, refreshString string, guid string) error {
	unID, err := produceUniqueID(refreshToken, guid)
	if err != nil {
		return err
	}

	alreadyThere := wr.DB.FindIfContains(unID)
	if alreadyThere {
		return models.ErrTokenOccupied
	}

  crypted, err := auth.ProduceBcrypt(refreshString)
	if err != nil {
		return err
	}

	err = wr.DB.InsertRefreshTokenHash(unID, crypted)
	if err != nil {
		return err
	}

	defer wr.scheduleDeletingToken(unID, auth.REFRESH_TOKEN_LIFETIME)
	return nil
}

func (wr *WrapperAPI) scheduleDeletingToken(unidKey string, duration time.Duration) {
	go func() {
		time.Sleep(duration)
		wr.DB.DeleteRefreshTokenHash(unidKey)
	}()
}


