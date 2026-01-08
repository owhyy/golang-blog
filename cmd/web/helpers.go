package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"owhyy/simple-auth/internal/models"
	"owhyy/simple-auth/internal/types"
	"owhyy/simple-auth/ui/templates"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/a-h/templ"
)

func (app *application) render(w http.ResponseWriter, r *http.Request, status int, title string, main templ.Component) {
	w.WriteHeader(status)

	navComponent := templates.Nav(app.isAuthenticated(r))
	templates.Base(title, navComponent, main).Render(r.Context(), w)
}

func (app *application) serverError(w http.ResponseWriter, r *http.Request, err error) {
	var (
		method = r.Method
		uri    = r.URL.RequestURI()
	)
	app.errorLog.Println(err.Error(), "method", method, "uri", uri)
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

func (app *application) clientError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}

func (app *application) isAuthenticated(r *http.Request) bool {
	session, err := app.cookieStore.Get(r, "auth-session")
	if err != nil {
		return false
	}
	return session.Values["userID"] != nil && !session.IsNew
}

func (app *application) getAuthenticatedUser(r *http.Request) *models.User {
	session, err := app.cookieStore.Get(r, "auth-session")
	if err != nil {
		return nil
	}
	id, ok := session.Values["userID"].(uint)
	if !ok || session.IsNew {
		return nil
	}

	user, err := app.users.GetByID(id)
	if err != nil {
		return nil
	}
	return user
}

func (app *application) renderHTMXSuccess(w http.ResponseWriter, msg string) {
	w.Write([]byte(`<p class="pico-color-green-600">` + msg + "</p>"))
}

func (app *application) renderHTMXError(w http.ResponseWriter, msg string) {
	w.Write([]byte(`<p class="pico-color-red-600">` + msg + "</p>"))
}

func (app *application) newPagination(r *http.Request) (*types.PaginationData, error) {
	var err error

	data := &types.PaginationData{}

	curPage := 1
	if s := r.URL.Query().Get("page"); s != "" {
		curPage, err = strconv.Atoi(s)
		if err != nil {
			return nil, err
		}
	}
	data.CurrentPage = curPage

	perPage := 30
	if s := r.URL.Query().Get("per_page"); s != "" {
		perPage, err = strconv.Atoi(s)
		if err != nil {
			return nil, err
		}
	}
	if perPage == 30 || perPage == 60 || perPage == 90 {
		data.PerPage = perPage
	} else {
		data.PerPage = 30
	}

	data.Prev = curPage - 1
	data.Next = curPage + 1

	return data, nil
}

func (app *application) saveUploadedFile(r *http.Request, formField string) (*string, error) {
	file, header, err := r.FormFile(formField)
	if err != nil {
		if err == http.ErrMissingFile {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	contentType := header.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "image/") {
		return nil, fmt.Errorf("invalid file type: %s. Only images are allowed", contentType)
	}
	const maxFileSize = 10 << 20 // 10MB
	if header.Size > maxFileSize {
		return nil, fmt.Errorf("file too large: %d bytes. Maximum size is 10MB", header.Size)
	}

	ext := filepath.Ext(header.Filename)
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, err
	}
	filename := hex.EncodeToString(randomBytes) + ext

	uploadsDir := "uploads"
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create uploads directory: %w", err)
	}
	filePath := filepath.Join(uploadsDir, filename)
	dst, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create file: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		os.Remove(filePath)
		return nil, fmt.Errorf("failed to save file: %w", err)
	}

	relativePath := "/uploads/" + filename
	return &relativePath, nil
}
