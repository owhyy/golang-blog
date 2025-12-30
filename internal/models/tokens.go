package models

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"
)

const emailVerificationTokenLength = 32
const emailVerificationTokenTTL = 30 * time.Minute

const passwordResetTokenLength = 32
const passwordResetTokenTTL = 10 * time.Minute

type TokenPurpose string

const (
	PasswordResetPurpose TokenPurpose = "password_reset"
	EmailVerifyPurpose   TokenPurpose = "email_verification"
)

type Token struct {
	ID        uint
	UserID    uint
	Token     string
	ExpiresAt time.Time
	CreatedAt time.Time
	UsedAt    sql.NullTime
	Purpose   TokenPurpose
}

type TokenModel struct {
	DB *DB
}

func generateRandomToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}

func (m *TokenModel) createToken(userID uint, purpose TokenPurpose, length int, ttl time.Duration) (string, error) {
	token, err := generateRandomToken(length)
	if err != nil {
		return "", err
	}

	expiresAt := time.Now().Add(ttl)

	_, err = m.DB.Exec(
		`INSERT INTO tokens (user_id, token, expires_at, purpose) VALUES (?, ?, ?, ?)`,
		userID, token, expiresAt, purpose,
	)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (m *TokenModel) CreateEmailVerificationToken(userID uint) (string, error) {
	return m.createToken(userID, EmailVerifyPurpose, emailVerificationTokenLength, emailVerificationTokenTTL)
}

func (m *TokenModel) CreatePasswordResetToken(userID uint) (string, error) {
	return m.createToken(userID, PasswordResetPurpose, passwordResetTokenLength, passwordResetTokenTTL)
}

var ErrInvalidOrExpiredToken = errors.New("invalid or expired token")

func (m *TokenModel) ExistsValid(purpose TokenPurpose, token string) (bool, error) {
	var exists bool
	err := m.DB.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM tokens WHERE purpose = $1 AND token = $2 AND used_at ISNULL AND DATE(expires_at) >= DATE('now'))",
		purpose, token).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (m *TokenModel) Consume(purpose TokenPurpose, token string) (uint, error) {
	var (
		userID    uint
		expiresAt time.Time
		usedAt    sql.NullTime
	)
	err := m.DB.QueryRow(
		`SELECT user_id, expires_at, used_at
         FROM tokens
         WHERE purpose = ? AND token = ?`,
		purpose, token,
	).Scan(&userID, &expiresAt, &usedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrInvalidOrExpiredToken
		}
		return 0, err
	}

	if usedAt.Valid || time.Now().After(expiresAt) {
		return 0, ErrInvalidOrExpiredToken
	}

	_, err = m.DB.Exec(
		`UPDATE tokens SET used_at = CURRENT_TIMESTAMP WHERE purpose = ? AND token = ?`,
		purpose, token,
	)
	if err != nil {
		return 0, err
	}

	return userID, nil
}
