package models

type User struct {
	ID           string `json:"id" bson:"_id"`
	RefreshToken string `json:"refreshToken" bson:"refreshToken"`
}
