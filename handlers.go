package main

import (
	_ "embed"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"net/http"
)

//go:embed html/home.html
var homeTmpl string

//go:embed html/login.html
var loginTmpl string

//go:embed html/signup.html
var signUpTmpl string

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
		return
	}
}

func (app *application) login(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/login" {
		http.NotFound(w, r)
		return
	}

	if r.Method == http.MethodGet {
		ts, err := template.New("home").Parse(loginTmpl)
		if err != nil {
			app.errorLog.Println(err.Error())
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		err = ts.ExecuteTemplate(w, "login", nil)
		if err != nil {

			app.errorLog.Println(err.Error())
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		return
	}

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			app.errorLog.Println(err.Error())
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		email := r.PostForm.Get("email")
		password := r.PostForm.Get("password")

		// TODO: replace this with db lookup
		if email == "user@example.com" && password == "password123" {
			w.Header().Set("HX-Redirect", "/")
			w.WriteHeader(http.StatusOK)
			return
		}

		w.Write([]byte(`<p style="color: red;">Invalid email or password</p>`))
	}

	w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func (app *application) signup(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/signup" {
		http.NotFound(w, r)
		return
	}

	if r.Method == http.MethodGet {
		ts, err := template.New("signup").Parse(signUpTmpl)
		if err != nil {
			app.errorLog.Println(err.Error())
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		err = ts.ExecuteTemplate(w, "signup", nil)
		if err != nil {
			app.errorLog.Println(err.Error())
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		return
	}

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			w.Write([]byte("Bad Request"))
			return
		}

		email := r.PostForm.Get("email")
		password := r.PostForm.Get("password")
		confirmPassword := r.PostForm.Get("confirm_password")

		// Validation
		if email == "" || password == "" {
			w.Write([]byte("<p style='color: red;'>Email and password are required</p>"))
			return
		}

		if len(password) < 8 {
			w.Write([]byte("<p style='color: red;'>Password must be at least 8 characters</p>"))
			return
		}

		if password != confirmPassword {
			w.Write([]byte("<p style='color: red;'>Passwords do not match</p>"))
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			app.errorLog.Println(err.Error())
			w.Write([]byte("<p style='color: red;'>Failed to create an account</p>"))
			return
		}

		// TODO: Save user to database
		app.infoLog.Printf("New user signed up: %s:%s", email, hashedPassword)

		w.Header().Set("HX-Redirect", "/login")
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}
