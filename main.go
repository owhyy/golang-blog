package main

import (
	"net/http"
	_ "embed"	
	"os"
	"log"
	"html/template"
)


type SimpleAuthService struct {
	client *http.Client
}

type application struct {
	simpleAuthService     *SimpleAuthService
	errorLog              *log.Logger
	infoLog               *log.Logger
}


//go:embed html/home.html
var homeTmpl string


func (app *application) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	
	ts, err := template.New("home").Parse(homeTmpl)
		if err != nil {
		app.errorLog.Println(err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
		}
	
	err = ts.ExecuteTemplate(w, "home", nil)
		if err != nil {
			app.errorLog.Println(err.Error())
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
}

func main() {
	infoLog := log.New(os.Stdout, "INFO\t", log.LstdFlags)
	errorLog := log.New(os.Stderr, "ERROR\t", log.LstdFlags|log.Lshortfile)

	app := &application{
		simpleAuthService: &SimpleAuthService{client: &http.Client{}},
		errorLog:              errorLog,
		infoLog:               infoLog,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.home)

	srv := &http.Server{Addr: "0.0.0.0:8080", ErrorLog: errorLog, Handler: mux}
	infoLog.Println("Starting server on 0.0.0.0:8080")
	
	err := srv.ListenAndServe()
	errorLog.Fatal(err)
}
