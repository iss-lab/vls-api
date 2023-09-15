package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func HealthController(c *gin.Context) {
	c.String(http.StatusOK, "Alive!")
}
