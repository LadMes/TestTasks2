package middleware

import (
	//"fmt"

	"net/http"
	"net/url"

	"github.com/LadMes/TestTasks2/controllers"
	jwtHelper "github.com/LadMes/TestTasks2/helpers"
	"github.com/LadMes/TestTasks2/models"
	"github.com/gin-gonic/gin"
)

func Authentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		//clientToken := c.Request.Header.Get("token")
		clientCookie, err := c.Request.Cookie("token")
		if err != nil {
			location := url.URL{Path: "/auth/signin"}
			c.Redirect(http.StatusFound, location.RequestURI())
			return
		}

		claims, msg := jwtHelper.ValidateToken(clientCookie.Value)
		if msg != "" {
			if msg == models.ExpiredAccessAndRefresh {
				location := url.URL{Path: "/auth/signin"}
				c.Redirect(http.StatusFound, location.RequestURI())
				return
			} else if msg == models.TokenWillSoonExpire || msg == models.ExpiredOnlyAccessToken {
				controllers.Refresh(claims.ID, c)
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
				c.Abort()
				return
			}
		}

		c.Set("id", claims.ID)

		c.Next()
	}
}
