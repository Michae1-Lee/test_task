package service

import (
	"golang.org/x/crypto/bcrypt"
	"test_task/domain"
	"test_task/repository"
)

type UserService struct {
	repo repository.UserRepository
}

func NewUserService(repo repository.UserRepository) *UserService {
	return &UserService{repo: repo}
}

func (s *UserService) Find(email string) (domain.User, error) {
	return s.repo.Find(email)
}

func (s *UserService) CreateNewUser(user domain.User) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hash)
	return s.repo.CreateUser(user)
}
