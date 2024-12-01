package types

type LoginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
