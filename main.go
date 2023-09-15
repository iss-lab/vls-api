package main

import (
	"vls-api/controllers"
	_ "vls-api/utils"

	"github.com/gin-gonic/gin"
)

func main() {

	server := gin.Default()

	server.GET("/", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{
			"Message": "Send Request on /scan",
		})
	})

	server.POST("/scan", controllers.GetVulnerability)
	server.GET("/health", controllers.HealthController)
	server.Run(":3000")

}
