package middleware

import (
	"net/http"
	"net/url"

	"github.com/LadMes/TestTasks2/controllers"
	"github.com/LadMes/TestTasks2/helpers"
	"github.com/LadMes/TestTasks2/models"
	"github.com/gin-gonic/gin"
)

func Authentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		accessCookie, err := c.Request.Cookie("token")
		if err != nil {
			location := url.URL{Path: "/auth/signin"}
			c.Redirect(http.StatusFound, location.RequestURI())
			c.Abort()
			return
		}

		refreshCookie, err := c.Request.Cookie("refreshToken")
		if err != nil {
			location := url.URL{Path: "/auth/signin"}
			c.Redirect(http.StatusFound, location.RequestURI())
			c.Abort()
			return
		}

		accessClaims, msg := helpers.ValidateToken(accessCookie.Value)
		refreshClaims, refMsg := helpers.ValidateToken(refreshCookie.Value)
		var id string
		if accessClaims != nil {
			id = accessClaims.ID.String()
		} else {
			id = refreshClaims.ID.String()
		}

		if msg != "" {
			if IsBothTokenExpired(msg, refMsg) {
				location := url.URL{Path: "/auth/signin"}
				c.Redirect(http.StatusFound, location.RequestURI())
				c.Abort()
				return
			} else if IsRefreshTokenValid(refMsg) {
				userInfoFromCookie := models.User{
					ID:            id,
					Refresh_token: refreshCookie.Value,
				}
				err := controllers.Refresh(userInfoFromCookie, c)
				if err != nil {
					c.Abort()
					return
				}
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error1": msg, "error2": refMsg})
				c.Abort()
				return
			}
		}

		c.Set("id", id)

		c.Next()
	}
}

func IsBothTokenExpired(acsMsg string, refMsg string) bool {
	return acsMsg == models.ExpiredToken && refMsg == models.ExpiredToken
}

func IsRefreshTokenValid(refMsg string) bool {
	return refMsg == models.TokenWillSoonExpire || refMsg == ""
}
