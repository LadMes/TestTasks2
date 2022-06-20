package helpers

import (
	"log"

	"golang.org/x/crypto/bcrypt"
)

func Hash(rt []byte) string {
	hash, err := bcrypt.GenerateFromPassword(rt, bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}

func CompareRefreshTokens(hashedRT string, plainRT []byte) bool {
	byteHash := []byte(hashedRT)

	err := bcrypt.CompareHashAndPassword(byteHash, plainRT)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}
