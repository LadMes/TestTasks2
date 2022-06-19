package controllers

import (
	"context"
	//"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/LadMes/TestTasks2/database"
	jwtHelper "github.com/LadMes/TestTasks2/helpers"
	"github.com/LadMes/TestTasks2/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

func SignUp() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		var user models.User

		user.ID = uuid.New().String()

		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			msg := "User item was not created"
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User with this ID doesn't exist"})
			return
		}

		expiresAt := time.Now().Add(20 * time.Minute)
		userID, err := uuid.Parse(foundUser.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "ID error"})
			return
		}
		token, refreshToken := jwtHelper.GenerateAllTokens(userID)
		jwtHelper.UpdateRefreshToken(refreshToken, userID)

		http.SetCookie(c.Writer, &http.Cookie{
			Name:    "token",
			Value:   token,
			Expires: expiresAt,
			Path:    "/",
		})
		c.JSON(http.StatusOK, foundUser)
	}
}

func Refresh(id uuid.UUID, c *gin.Context) {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var foundUser models.User
	err := userCollection.FindOne(ctx, bson.M{"_id": id.String()}).Decode(&foundUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User with this ID doesn't exist"})
		return
	}
	expiresAt := time.Now().Add(20 * time.Minute)
	userID, err := uuid.Parse(foundUser.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ID error"})
		return
	}
	token, refreshToken := jwtHelper.GenerateAllTokens(userID)
	jwtHelper.UpdateRefreshToken(refreshToken, userID)

	http.SetCookie(c.Writer, &http.Cookie{
		Name:    "token",
		Value:   token,
		Expires: expiresAt,
		Path:    "/",
	})
}
