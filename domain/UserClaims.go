package domain

import "github.com/golang-jwt/jwt/v5"

type UserClaims struct {
	Id    string
	Email string
	Ip    string
	jwt.RegisteredClaims
}
