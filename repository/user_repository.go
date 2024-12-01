package repository

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/jmoiron/sqlx"
	"test_task/domain"
)

type UserRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Find(email string) (domain.User, error) {
	query := `SELECT id, email, password FROM users WHERE email = $1`

	row := r.db.QueryRow(query, email)

	var user domain.User
	err := row.Scan(&user.Id, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.User{}, errors.New("user not found")
		}
		return domain.User{}, fmt.Errorf("error querying user by email: %w", err)
	}

	return user, nil
}

func (r *UserRepository) CreateUser(user domain.User) error {
	query := `INSERT INTO users (id, email, password) VALUES ($1, $2, $3)`

	_, err := r.db.Exec(query, user.Id, user.Email, user.Password)
	if err != nil {
		return fmt.Errorf("error inserting user: %w", err)
	}

	return nil
}
