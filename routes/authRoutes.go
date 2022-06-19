package routes

import (
	controller "github.com/LadMes/TestTasks2/controllers"

	"github.com/gin-gonic/gin"
)

func AuthRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("/auth/signin", controller.SignIn())
	incomingRoutes.POST("/auth/signup", controller.SignUp())
}
