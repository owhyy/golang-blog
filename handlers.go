package main

import (
	_ "embed"
	"errors"
	"html/template"
	"net/http"

	"owhyy/simple-auth/models"
)

//go:embed html/home.html
var homeTmpl string

//go:embed html/login.html
var loginTmpl string

//go:embed html/signup.html
var signUpTmpl string

//go:embed html/verify.html
var verifyTmpl string

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

		err = app.users.Authenticate(email, password)
		if err != nil {
			msg := "Authentication error"
			if errors.Is(err, models.ErrInvalidCredentials) {
				msg = "Invalid email or password"
			}
			app.errorLog.Println(err.Error())
			w.Write([]byte(`<p style="color: red;">` + msg + "</p>"))
			return
		}

		app.infoLog.Printf("User logged in: %s", email)

		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
		return
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

		userId, err := app.users.Create(email, password)
		app.infoLog.Println(userId)
		if err != nil {
			var msg = "Failed to create account"
			if errors.Is(err, models.ErrDuplicateEmail) {
				msg = "An user with this email already exists"
			}

			w.Write([]byte("<p style='color: red;'>" + msg + "</p>"))
			app.errorLog.Println(err.Error())
			return
		}

		token, err := app.tokens.Create(userId)
		if err != nil {
			app.errorLog.Println("Failed to create token " + err.Error())
		}
		app.infoLog.Println("Token " + token + " created for " + email)
		err = app.emailService.SendVerificationEmail(email, app.config.BaseURL, token)
		// Should we display error to front-end or not?
		if err != nil {
			app.errorLog.Println("Failed to send verification email to " + email + err.Error())
		}

		w.Header().Set("HX-Redirect", "/login")
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func (app *application) verify(w http.ResponseWriter, r *http.Request) {
	data := struct{ Error string }{}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	ts, err := template.New("verify").Parse(verifyTmpl)
	if err != nil {
		app.errorLog.Println(err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		data.Error = "Verification link is invalid. Try requesting a new verification link after logging in"
		err = ts.ExecuteTemplate(w, "verify", data)
		if err != nil {
			app.errorLog.Println(err.Error())
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		return
	}
	// TODO: ideally this proccess should be atomic
	// but for an MVP it's alright
	userID, err := app.tokens.Consume(token)
	if err != nil {
		data.Error = "Token has already been used or is expired. Please request a new verification link after logging in"
		err = ts.ExecuteTemplate(w, "verify", data)
		if err != nil {
			app.errorLog.Println(err.Error())
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		return
	}

	err = app.users.ValidateByID(userID)
	if err != nil {
		data.Error = "Something went wrong. Please try again later"
		app.errorLog.Println("verify: failed to validate user:", err)
		err = ts.ExecuteTemplate(w, "verify", data)
		if err != nil {
			app.errorLog.Println(err.Error())
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		return
	}

	app.infoLog.Printf("User %d validated", userID)
	err = ts.ExecuteTemplate(w, "verify", data)

	if err != nil {
		app.errorLog.Println(err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}

	email, err := app.users.GetEmailByID(userID)
	if err != nil {
		app.errorLog.Println(err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}

	err = app.emailService.SendAccountVerifiedEmail(email)
	if err != nil {
		app.errorLog.Println("Failed send verification email to " + email + err.Error())
	}

}
