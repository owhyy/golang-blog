package main

import (
	"embed"
	"log"
	"net/http"
	"os"

	"owhyy/simple-auth/models"
	"owhyy/simple-auth/services"
)

//go:embed static/*
var staticFS embed.FS

type application struct {
	config   *Config
	errorLog *log.Logger
	infoLog  *log.Logger
	users    *models.UserModel
	tokens   *models.ValidationTokenModel

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
	defer db.Close()

	app := &application{
		config:   config,
		errorLog: errorLog,
		infoLog:  infoLog,
		users:    &models.UserModel{DB: db},
		tokens:   &models.ValidationTokenModel{DB: db},
		emailService: services.NewEmailService(
			config.SMTPHost,
			config.SMTPPort,
			config.SMTPUsername,
			config.SMTPPassword,
			config.SMTPFrom,
		),
	}

	mux := http.NewServeMux()

	fileServer := http.FileServer(http.FS(staticFS))
	mux.Handle("/static/", fileServer)

	mux.HandleFunc("/", app.home)
	mux.HandleFunc("/login", app.login)
	mux.HandleFunc("/signup", app.signup)
	mux.HandleFunc("/verify", app.verify)

	srv := &http.Server{Addr: "0.0.0.0:8080", ErrorLog: errorLog, Handler: mux}
	infoLog.Println("Starting server on 0.0.0.0:8080")

	err = srv.ListenAndServe()
	errorLog.Fatal(err)
}
