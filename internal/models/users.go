package models

import (
	"database/sql"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrDuplicateEmail     = errors.New("email already exists")
	ErrDuplicateUsername  = errors.New("username already exists")
	ErrInvalidCredentials = errors.New("invalid email or password")
)

type User struct {
	ID            uint
	Username      string
	Email         string
	PasswordHash  string
	EmailVerified bool
	CreatedAt     string
}

type UserModel struct {
	DB *DB
}

func (m *UserModel) SetPassword(id uint, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = m.DB.Exec("UPDATE users SET password_hash = $1 WHERE id = $2", id, string(hashedPassword))
	if err != nil {
		return err
	}

	return nil
}

func (m *UserModel) Create(email, username, password string) (uint, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}

	result, err := m.DB.Exec(
		"INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
		email, username, string(hashedPassword),
	)

	if err != nil {
		if err.Error() == "UNIQUE constraint failed: users.email" {
			return 0, ErrDuplicateEmail
		}
		if err.Error() == "UNIQUE constraint failed: users.username" {
			return 0, ErrDuplicateUsername
		}
		return 0, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return uint(id), nil
}

func (m *UserModel) Authenticate(email, password string) (uint, error) {
	var id uint
	var passwordHash string

	err := m.DB.QueryRow(
		"SELECT id, password_hash FROM users WHERE email = ?",
		email,
	).Scan(&id, &passwordHash)

	if err != nil {
		if err == sql.ErrNoRows {
			return 0, ErrInvalidCredentials
		}
		return 0, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		return 0, ErrInvalidCredentials
	}

	return id, nil
}

func (m *UserModel) VerifyEmailByID(id uint) error {
	_, err := m.DB.Exec(
		`UPDATE users SET email_verified = 1 WHERE id = ?`,
		id,
	)
	return err
}

func (m *UserModel) GetEmailByID(id uint) (string, error) {
	var email string
	err := m.DB.QueryRow(
		"SELECT email FROM users WHERE id = ?",
		id,
	).Scan(&email)

	return email, err
}

func (m *UserModel) GetByID(id uint) (*User, error) {
	user := &User{}
	err := m.DB.QueryRow(
		"SELECT id, email, email_verified, created_at FROM users WHERE id = ?",
		id,
	).Scan(
		&user.ID,
		&user.Email,
		&user.EmailVerified,
		&user.CreatedAt,
	)
	return user, err
}

func (m *UserModel) GetByEmail(email string) (*User, error) {
	user := &User{}
	err := m.DB.QueryRow(
		"SELECT id, email, email_verified, created_at FROM users WHERE email = ?",
		email,
	).Scan(
		&user.ID,
		&user.Email,
		&user.EmailVerified,
		&user.CreatedAt,
	)
	return user, err
}

func (m *UserModel) CanCreatePasswordRequest(id uint) (bool, error) {
	var count int
	err := m.DB.QueryRow(
		"SELECT count(1) FROM tokens WHERE user_id = ? AND DATE(created_at) = DATE('now')",
		id,
	).Scan(
		&count,
	)
	return count < 4, err
}
