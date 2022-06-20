package controllers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/LadMes/TestTasks2/database"
	"github.com/LadMes/TestTasks2/helpers"
	"github.com/LadMes/TestTasks2/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

// For testing purpose I added SingUp route
func SignUp() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		var user models.User

		user.ID = uuid.New().String()

		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User has not been created"})
			return
		}

		c.JSON(http.StatusOK, resultInsertionNumber)
	}
}

func SignIn() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		var user models.User
		var foundUser models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}

		err := userCollection.FindOne(ctx, bson.M{"_id": user.ID}).Decode(&foundUser)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User with this ID doesn't exist"})
			return
		}

		userID, err := uuid.Parse(foundUser.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		token, refreshToken := helpers.GenerateAllTokens(userID)
		helpers.UpdateRefreshToken(helpers.Hash([]byte(refreshToken)), userID)

		SetAllCookies(c, token, refreshToken)

		c.JSON(http.StatusOK, foundUser)
	}
}

func Refresh(userInfoFromCookie models.User, c *gin.Context) error {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var foundUser models.User
	err := userCollection.FindOne(ctx, bson.M{"_id": userInfoFromCookie.ID}).Decode(&foundUser)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User with this ID doesn't exist"})
		return err
	}

	comparison := helpers.CompareRefreshTokens(foundUser.Refresh_token, []byte(userInfoFromCookie.Refresh_token))
	if !comparison {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh tokens are not the same"})
	}

	userID, err := uuid.Parse(foundUser.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return err
	}
	token, refreshToken := helpers.GenerateAllTokens(userID)
	helpers.UpdateRefreshToken(helpers.Hash([]byte(refreshToken)), userID)

	SetAllCookies(c, token, refreshToken)
	return nil
}

func SetAllCookies(c *gin.Context, token string, refreshToken string) {
	refreshTokenExpiresAt := time.Now().Add(models.RefreshTokenMultiplier * time.Minute)

	http.SetCookie(c.Writer, &http.Cookie{
		Name:    "token",
		Value:   token,
		Expires: refreshTokenExpiresAt,
		Path:    "/",
	})

	http.SetCookie(c.Writer, &http.Cookie{
		Name:    "refreshToken",
		Value:   refreshToken,
		Expires: refreshTokenExpiresAt,
		Path:    "/",
	})
}
