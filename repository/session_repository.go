package repository

import (
	"context"
	"fmt"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"test_task/domain"
)

type SessionRepository struct {
	db *sqlx.DB
}

func NewSessionRepository(db *sqlx.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (ps *SessionRepository) CreateSession(ctx context.Context, s *domain.Session) (*domain.Session, error) {

	_, err := ps.db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_email, ip, refresh_token, access_token, expires_at) 
		VALUES ($1, $2, $3, $4, $5, $6)`,
		s.Id, s.UserEmail, s.Ip, s.RefreshToken, s.AccessToken, s.ExpiresAt)

	if err != nil {
		return nil, fmt.Errorf("error inserting session: %w", err)
	}

	return s, nil
}

func (ps *SessionRepository) GetSession(ctx context.Context, id string) (*domain.Session, error) {

	var s domain.Session
	err := ps.db.GetContext(ctx, &s, "SELECT * FROM sessions WHERE id=$1", id)
	if err != nil {
		return nil, fmt.Errorf("error getting session: %w", err)
	}

	return &s, nil
}
