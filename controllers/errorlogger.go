package controllers

import "github.com/gin-gonic/gin"

func FormatErrors(c *gin.Context) {
	c.Next()

	if len(c.Errors) >= 1 {
		foundError := c.Errors[len(c.Errors)-1]
		c.JSON(-1, foundError)
	}
}
