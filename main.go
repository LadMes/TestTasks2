package main

import (
	"os"

	middleware "github.com/LadMes/TestTasks2/middleware"
	routes "github.com/LadMes/TestTasks2/routes"

	"github.com/gin-gonic/gin"
)

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		port = "8000"
	}

	router := gin.New()
	router.Use(gin.Logger())
	routes.AuthRoutes(router)

	router.Use(middleware.Authentication())

	// test-api
	router.GET("/test-api", func(c *gin.Context) {
		c.JSON(200, gin.H{"success": "Access granted for test-api"})
	})

	router.Run(":" + port)
}
