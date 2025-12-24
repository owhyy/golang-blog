package main

import (
	"embed"
	"log"
	"net/http"
	"os"

	"owhyy/simple-auth/models"
	"owhyy/simple-auth/services"

	"github.com/gorilla/sessions"
)

//go:embed static/*
var staticFS embed.FS

type application struct {
	config      *Config
	errorLog    *log.Logger
	infoLog     *log.Logger
	users       *models.UserModel
	tokens      *models.TokenModel
	cookieStore *sessions.CookieStore

	emailService *services.EmailService
}

func main() {
	infoLog := log.New(os.Stdout, "INFO\t", log.LstdFlags)
	errorLog := log.New(os.Stderr, "ERROR\t", log.LstdFlags|log.Lshortfile)

	config, err := LoadConfig()
	if err != nil {
		errorLog.Fatal(err)
	}

	db, err := models.NewDB("./users.db")
	if err != nil {
		errorLog.Fatal(err)
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

	fileServer := http.FileServer(http.FS(staticFS))
	mux.Handle("GET /static/", fileServer)

	mux.HandleFunc("GET /", app.home)
	mux.HandleFunc("GET /login", app.loginGet)
	mux.HandleFunc("POST /login", app.loginPost)
	mux.HandleFunc("GET /signup", app.signupGet)
	mux.HandleFunc("POST /signup", app.signupPost)
	mux.HandleFunc("GET /verify", app.verify)
	mux.HandleFunc("GET /profile", app.profile)
	mux.HandleFunc("POST /logout", app.logout)
	mux.HandleFunc("POST /request-password-reset", app.requestPasswdReset)

	srv := &http.Server{Addr: "0.0.0.0:8080", ErrorLog: errorLog, Handler: mux}
	infoLog.Println("Starting server on 0.0.0.0:8080")

	err = srv.ListenAndServe()
	errorLog.Fatal(err)
}
