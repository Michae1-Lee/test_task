package types

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
