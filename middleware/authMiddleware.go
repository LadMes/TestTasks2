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
		if msg != "" {
			if isIdEqual(accessClaims.Id, refreshClaims.Id) {
				if isBothTokenExpired(msg, refMsg) {
					location := url.URL{Path: "/auth/signin"}
					c.Redirect(http.StatusFound, location.RequestURI())
					c.Abort()
					return
				} else if isRefreshTokenValid(refMsg) {
					userInfoFromCookie := models.User{
						ID:           accessClaims.ID.String(),
						RefreshToken: refreshCookie.Value,
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
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "You don't have access"})
				c.Abort()
				return
			}
		}

		c.Set("id", accessClaims.ID.String())

		c.Next()
	}
}

func isIdEqual(accessId string, refreshId string) bool {
	return accessId == refreshId
}

func isBothTokenExpired(acsMsg string, refMsg string) bool {
	return acsMsg == models.ExpiredToken && refMsg == models.ExpiredToken
}

func isRefreshTokenValid(refMsg string) bool {
	return refMsg == models.TokenWillSoonExpire || refMsg == ""
}
