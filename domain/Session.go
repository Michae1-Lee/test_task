package domain

import "time"

type Session struct {
	Id           string    `db:"id"`
	UserEmail    string    `db:"user_email"`
	Ip           string    `db:"ip"`
	RefreshToken string    `db:"refresh_token"`
	AccessToken  string    `db:"access_token"`
	CreatedAt    time.Time `db:"created_at"`
	ExpiresAt    time.Time `db:"expires_at"`
}
