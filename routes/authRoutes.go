package routes

import (
	controller "github.com/LadMes/TestTasks2/controllers"

	"github.com/gin-gonic/gin"
)

func AuthRoutes(incomingRoutes *gin.Engine) {
	// For testing purpose I added SingUp route
	incomingRoutes.POST("/auth/signin", controller.SignIn())
	incomingRoutes.POST("/auth/signup", controller.SignUp())
	incomingRoutes.POST("/auth/refresh", controller.Refresh())
}
