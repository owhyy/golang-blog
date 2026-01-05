package models

import (
	"database/sql"
	"errors"
	"time"
)

type PostStatus string

var ErrRecordNotFound = errors.New("record not found")

const (
	Draft     PostStatus = "draft"
	Published PostStatus = "published"
)

type Post struct {
	ID             uint
	Title          string
	Slug           string
	Content        string
	Excerpt        string
	AuthorID       uint
	AuthorUsername string // not saved in db
	Status         PostStatus
	PublishedAt    *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
	FeaturedImage  *string
}

type PostModel struct {
	DB *DB
}

func (m *PostModel) GetPublished(perPage, currentPage int) ([]Post, error) {
	query := `
		SELECT
			id,
			title,
			slug,
			content,
			excerpt,
			author_id,
			status,
			published_at,
			created_at,
			updated_at,
			featured_image
		FROM posts
		WHERE status = 'published'
		ORDER BY published_at DESC
		LIMIT $1
                OFFSET $2
	`

	rows, err := m.DB.Query(query, perPage, (currentPage-1)*perPage)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []Post

	for rows.Next() {
		var p Post

		err := rows.Scan(
			&p.ID,
			&p.Title,
			&p.Slug,
			&p.Content,
			&p.Excerpt,
			&p.AuthorID,
			&p.Status,
			&p.PublishedAt,
			&p.CreatedAt,
			&p.UpdatedAt,
			&p.FeaturedImage,
		)
		if err != nil {
			return nil, err
		}

		posts = append(posts, p)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return posts, nil
}

func (m *PostModel) GetBySlug(slug string) (*Post, error) {
	query := `
		SELECT
			p.id,
			p.title,
			p.slug,
			p.content,
			p.excerpt,
			p.author_id,
                        u.username,
			p.status,
			p.published_at,
			p.created_at,
			p.updated_at,
			p.featured_image
		FROM posts p JOIN users u on p.author_id = u.id
		WHERE slug = $1
		LIMIT 1
	`

	var p Post

	err := m.DB.QueryRow(query, slug).Scan(
		&p.ID,
		&p.Title,
		&p.Slug,
		&p.Content,
		&p.Excerpt,
		&p.AuthorID,
		&p.AuthorUsername,
		&p.Status,
		&p.PublishedAt,
		&p.CreatedAt,
		&p.UpdatedAt,
		&p.FeaturedImage,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrRecordNotFound
		}
		return nil, err
	}

	return &p, nil
}

func (m *PostModel) GetByAuthorID(authorID uint, limit, currentPage int) ([]Post, error) {
	query := `
		SELECT
			id,
			title,
			slug,
			content,
			excerpt,
			author_id,
			status,
			published_at,
			created_at,
			updated_at,
			featured_image
		FROM posts
		WHERE author_id = $1
		ORDER BY published_at DESC
		LIMIT $2
                OFFSET $3
	`

	rows, err := m.DB.Query(query, authorID, limit, (currentPage-1)*limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []Post

	for rows.Next() {
		var p Post

		err := rows.Scan(
			&p.ID,
			&p.Title,
			&p.Slug,
			&p.Content,
			&p.Excerpt,
			&p.AuthorID,
			&p.Status,
			&p.PublishedAt,
			&p.CreatedAt,
			&p.UpdatedAt,
			&p.FeaturedImage,
		)
		if err != nil {
			return nil, err
		}

		posts = append(posts, p)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return posts, nil
}

func (m *PostModel) CountSlugs(slug string) (int, error) {
	var count int
	query := `
SELECT COUNT(1) FROM posts WHERE slug = $1 OR slug LIKE $2
`

	err := m.DB.QueryRow(query, slug, slug+"-%").Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}

func (m *PostModel) Create(p *Post) error {
	query := `
		INSERT INTO posts (
			title,
			slug,
			content,
			excerpt,
			author_id,
			status,
			published_at,
			featured_image
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := m.DB.Exec(
		query,
		p.Title,
		p.Slug,
		p.Content,
		p.Excerpt,
		p.AuthorID,
		p.Status,
		p.PublishedAt,
		p.FeaturedImage,
	)

	if err != nil {
		return err
	}

	return nil
}

func (m *PostModel) CountPublished() (int, error) {
	var count uint
	query := `SELECT COUNT(1) FROM posts WHERE status = $1`

	err := m.DB.QueryRow(query, Published).Scan(&count)
	if err != nil {
		return 0, err
	}

	return int(count), nil
}

func (m *PostModel) CountForUser(author_id uint) (int, error) {
	var count uint
	query := `SELECT COUNT(1) FROM posts WHERE author_id = $1`

	err := m.DB.QueryRow(query, author_id).Scan(&count)
	if err != nil {
		return 0, err
	}

	return int(count), nil
}
