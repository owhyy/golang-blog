package main

import (
	"log"
	"net/http"
	"os"
	"owhyy/simple-auth/internal"
	"owhyy/simple-auth/internal/models"
	"owhyy/simple-auth/internal/services"
	"owhyy/simple-auth/ui"

	"github.com/gorilla/sessions"
)

type application struct {
	config       *internal.Config
	errorLog     *log.Logger
	infoLog      *log.Logger
	users        *models.UserModel
	tokens       *models.TokenModel
	posts        *models.PostModel
	cookieStore  *sessions.CookieStore
	emailService *services.EmailService
}

func main() {
	infoLog := log.New(os.Stdout, "INFO\t", log.LstdFlags)
	errorLog := log.New(os.Stderr, "ERROR\t", log.LstdFlags|log.Lshortfile)

	config, err := internal.LoadConfig()
	if err != nil {
		errorLog.Fatal(err.Error())
	}

	db, err := models.Migrate("./app.db")
	if err != nil {
		errorLog.Fatal(err.Error())
	}
	defer func(db *models.DB) {
		err := db.Close()
		if err != nil {
			errorLog.Fatal(err)
		}
	}(db)

	var store = sessions.NewCookieStore([]byte(config.SessionKey))
	store.Options = &sessions.Options{SameSite: http.SameSiteLaxMode, Secure: false}

	app := &application{
		config:      config,
		errorLog:    errorLog,
		infoLog:     infoLog,
		users:       &models.UserModel{DB: db},
		tokens:      &models.TokenModel{DB: db},
		posts:       &models.PostModel{DB: db},
		cookieStore: store,
		emailService: &services.EmailService{
			Host:     config.SMTPHost,
			Port:     config.SMTPPort,
			Username: config.SMTPUsername,
			Password: config.SMTPPassword,
			From:     config.SMTPFrom,
		},
	}

	mux := http.NewServeMux()

	fileServer := http.FileServerFS(ui.Files)
	mux.Handle("GET /static/", fileServer)

	mux.HandleFunc("GET /uploads/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	})
	mux.HandleFunc("GET /uploads/{filename}", app.serveUpload)

	mux.HandleFunc("GET /", app.home)
	mux.HandleFunc("GET /login", app.loginGet)
	mux.HandleFunc("POST /login", app.loginPost)
	mux.HandleFunc("GET /signup", app.signupGet)
	mux.HandleFunc("POST /signup", app.signupPost)
	mux.HandleFunc("GET /verify", app.verify)
	mux.HandleFunc("GET /profile", app.requireAuthentication(app.profile))
	mux.HandleFunc("POST /logout", app.logout)
	mux.HandleFunc("GET /request-password-reset", app.requestPasswdResetGet)
	mux.HandleFunc("POST /request-password-reset", app.requestPasswdResetPost)
	mux.HandleFunc("GET /reset-password", app.resetPasswordGet)
	mux.HandleFunc("POST /reset-password", app.resetPasswordPost)
	mux.HandleFunc("GET /posts/view/", app.viewPost)
	mux.HandleFunc("GET /posts/user/{username}", app.userPosts)
	mux.HandleFunc("POST /posts/{id}/publish", app.requireAuthentication(app.publishPost))
	mux.HandleFunc("POST /posts/{id}/unpublish", app.requireAuthentication(app.unpublishPost))
	mux.HandleFunc("PATCH /posts/{id}/update", app.requireAuthentication(app.updatePost))
	mux.HandleFunc("PATCH /posts/{id}/update-image", app.requireAuthentication(app.updatePostImage))
	mux.HandleFunc("DELETE /posts/{id}/image", app.requireAuthentication(app.deletePostImage))
	mux.HandleFunc("DELETE /posts/{id}", app.requireAuthentication(app.deletePost))
	mux.HandleFunc("GET /posts/my", app.requireAuthentication(app.myPosts))
	mux.HandleFunc("GET /posts/create", app.requireAuthentication(app.postCreateGet))
	mux.HandleFunc("POST /posts/create", app.requireAuthentication(app.postCreatePost))

	srv := &http.Server{Addr: "0.0.0.0:8080", ErrorLog: errorLog, Handler: mux}
	infoLog.Println("Starting server on 0.0.0.0:8080")

	err = srv.ListenAndServe()
	errorLog.Fatal(err)
}
