package helpers

import (
	"context"

	"log"
	"os"
	"time"

	"github.com/LadMes/TestTasks2/database"
	"github.com/LadMes/TestTasks2/models"
	"github.com/google/uuid"

	jwt "github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Claims struct {
	ID uuid.UUID
	jwt.StandardClaims
}

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var SECRET_KEY string = os.Getenv("SECRET_KEY")

func GenerateAllTokens(id uuid.UUID) (signedToken string, signedRefreshToken string) {
	claims := &Claims{
		ID: id,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(models.AccessTokenMultiplier * time.Minute).Unix(),
		},
	}

	refreshClaims := &Claims{
		ID: id,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(models.RefreshTokenMultiplier * time.Minute).Unix(),
		},
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString([]byte(SECRET_KEY))

	if err != nil {
		log.Panic(err)
		return
	}

	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS512, refreshClaims).SignedString([]byte(SECRET_KEY))

	if err != nil {
		log.Panic(err)
		return
	}

	return token, refreshToken
}

func UpdateRefreshToken(signedRefreshToken string, id uuid.UUID) {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	var updateObj primitive.D
	updateObj = append(updateObj, bson.E{Key: "refreshToken", Value: signedRefreshToken})

	upsert := true
	filter := bson.M{"_id": id.String()}
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}

	_, err := userCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			{Key: "$set", Value: updateObj},
		},
		&opt,
	)
	defer cancel()

	if err != nil {
		log.Panic(err)
	}
}

func ValidateToken(signedToken string) (claims *Claims, msg string) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SECRET_KEY), nil
		},
	)

	claims, ok := token.Claims.(*Claims)
	if err != nil || !ok {
		return claims, models.InvalidToken
	}

	message := ""
	if claims.ExpiresAt < time.Now().Unix() {
		message = models.ExpiredToken
	} else if claims.ExpiresAt >= time.Now().Unix() && claims.ExpiresAt-time.Now().Unix() < int64(time.Minute/time.Second) {
		message = models.TokenWillSoonExpire
	}

	return claims, message
}
