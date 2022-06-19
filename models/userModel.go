package models

type User struct {
	ID            string `json:"id" bson:"_id"`
	Refresh_token string `json:"refreshToken" bson:"refreshToken"`
}
