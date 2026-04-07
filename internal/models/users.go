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
	IsAdmin       bool
}

type UserModel struct {
	DB *DB
}

func (m *UserModel) SetPassword(id uint, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = m.DB.Exec("UPDATE users SET password_hash = $1 WHERE id = $2", string(hashedPassword), id)
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
		"SELECT id, email, username, email_verified, is_admin, created_at FROM users WHERE id = ?",
		id,
	).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.EmailVerified,
		&user.IsAdmin,
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

func (m *UserModel) GetByUsername(username string) (*User, error) {
	user := &User{}
	err := m.DB.QueryRow(
		"SELECT id, email, username, email_verified, is_admin, created_at FROM users WHERE username = ?",
		username,
	).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.EmailVerified,
		&user.IsAdmin,
		&user.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrRecordNotFound
		}
		return nil, err
	}
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

func (m *UserModel) Delete(id uint) error {
	query := `DELETE FROM users WHERE id = ?`
	_, err := m.DB.Exec(query, id)
	return err
}

func (m *UserModel) GetAll(perPage, currentPage int) ([]User, error) {
	query := `
		SELECT id, email, username, email_verified, is_admin, created_at
		FROM users
		ORDER BY created_at DESC
		LIMIT ?
		OFFSET ?
	`

	rows, err := m.DB.Query(query, perPage, (currentPage-1)*perPage)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User

	for rows.Next() {
		var u User
		err := rows.Scan(
			&u.ID,
			&u.Email,
			&u.Username,
			&u.EmailVerified,
			&u.IsAdmin,
			&u.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

func (m *UserModel) Count() (int, error) {
	var count int
	err := m.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}
