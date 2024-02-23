package models

import (
	"encoding/hex"
	"errors"
	"strings"
)

type AuthTarget struct {
	GUID string `form:"guid" binding:"required"`
}

var ErrReceivedNoGUID = errors.New("No appropriate GUID passed in query parameters;")

func (at *AuthTarget) PutInOrderGUID() error {
	id := at.GUID
	if id == "" {
		return ErrReceivedNoGUID
	}

	id = strings.Trim(id, " ")
	if id[0] == '{' {
		// cutting off curly braces (if any)
		id = id[1 : len(id)-1]
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
