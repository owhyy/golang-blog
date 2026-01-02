package models

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	slug2 "github.com/gosimple/slug"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type DB struct {
	*sql.DB
}

func Migrate(dataSourceName string) (*DB, error) {
	db, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	createTablesSQL := `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at DATETIME,
    purpose TEXT NOT NULL
        CHECK (purpose IN ('password_reset', 'email_verification')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
    
CREATE TABLE IF NOT EXISTS posts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    slug        TEXT UNIQUE NOT NULL,            
    content     TEXT NOT NULL,                   
    excerpt     TEXT,                            
    author_id   INTEGER NOT NULL,                
    status      TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published')),   
    published_at DATETIME,                       
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    featured_image TEXT,
    
    FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_users_id ON users(id);
CREATE INDEX IF NOT EXISTS idx_tokens_id ON tokens(id);
CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token);
CREATE INDEX IF NOT EXISTS idx_tokens_purpose ON tokens(purpose);
CREATE INDEX IF NOT EXISTS idx_posts_slug ON posts(slug);
CREATE INDEX IF NOT EXISTS idx_posts_author_id ON posts(author_id);    
`
	_, err = db.Exec(createTablesSQL)
	if err != nil {
		return nil, err
	}

	return &DB{db}, nil
}

func Populate(db *DB, userCount int, postCount int) error {
	gofakeit.Seed(time.Now().UnixNano())

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	userIDs := make([]int64, 0, userCount)

	userQuery := `
		INSERT INTO users (email, username, password_hash, email_verified)
		VALUES %s
	`

	userValues := make([]string, 0, userCount)
	userArgs := make([]any, 0, userCount*4)

	for range userCount {
		pass := gofakeit.Password(true, true, true, true, false, 12)
		hashedPass, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		userValues = append(userValues, "(?, ?, ?, ?)")
		userArgs = append(userArgs,
			gofakeit.Email(),
			gofakeit.Username(),
			hashedPass,
			1,
		)
	}

	res, err := tx.Exec(
		fmt.Sprintf(userQuery, strings.Join(userValues, ",")),
		userArgs...,
	)
	if err != nil {
		return err
	}

	firstID, err := res.LastInsertId()
	if err != nil {
		return err
	}

	for i := range userCount {
		userIDs = append(userIDs, firstID+int64(i))
	}

	batchSize := postCount / 10

	postQuery := `
		INSERT INTO posts (
			title,
			slug,
			content,
			excerpt,
			author_id,
			status,
			published_at
		) VALUES %s
	`

	for i := 0; i < postCount; i += batchSize {
		values := make([]string, 0, batchSize)
		args := make([]any, 0, batchSize*7)

		limit := batchSize
		if i+limit > postCount {
			limit = postCount - i
		}

		for j := 0; j < limit; j++ {
			title := gofakeit.HipsterSentence()
			slug := slug2.Make(title) + "-" + gofakeit.UUID()
			content := gofakeit.HipsterParagraph()
			excerpt := content
			if len(excerpt) > 150 {
				excerpt = excerpt[:150]
			}

			authorID := userIDs[gofakeit.Number(0, len(userIDs)-1)]

			status := "published"
			publishedAt := sql.NullTime{
				Time:  gofakeit.DateRange(time.Now().AddDate(-1, 0, 0), time.Now()),
				Valid: true,
			}

			values = append(values, "(?, ?, ?, ?, ?, ?, ?)")
			args = append(args,
				title,
				slug,
				content,
				excerpt,
				authorID,
				status,
				publishedAt,
			)
		}

		_, err := tx.Exec(
			fmt.Sprintf(postQuery, strings.Join(values, ",")),
			args...,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
