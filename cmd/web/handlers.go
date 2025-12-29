package main

import (
	_ "embed"
	"errors"
	"net/http"
	"owhyy/simple-auth/internal/models"

	passwordvalidator "github.com/wagslane/go-password-validator"
)

func (app *application) home(w http.ResponseWriter, r *http.Request) {
	if app.isAuthenticated(r) {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}
	app.render(w, r, http.StatusOK, "home.html", templateData{})
}

func (app *application) profile(w http.ResponseWriter, r *http.Request) {
	user := app.getAuthenticatedUser(r)
	data := templateData{User: *user}
	app.render(w, r, http.StatusOK, "profile.html", data)
}

func (app *application) loginGet(w http.ResponseWriter, r *http.Request) {
	if app.isAuthenticated(r) {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	app.render(w, r, http.StatusOK, "login.html", templateData{})
}

func (app *application) loginPost(w http.ResponseWriter, r *http.Request) {
	if app.isAuthenticated(r) {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	session, err := app.cookieStore.Get(r, "auth-session")
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	err = r.ParseForm()
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	email := r.PostForm.Get("email")
	password := r.PostForm.Get("password")

	id, err := app.users.Authenticate(email, password)
	if err != nil {
		app.errorLog.Println(err.Error())
		msg := "Authentication error"
		if errors.Is(err, models.ErrInvalidCredentials) {
			msg = "Invalid email or password"
		}
		app.renderHTMXError(w, msg)
		return
	}

	session.Values["userID"] = id
	err = session.Save(r, w)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	app.infoLog.Printf("User logged in: %s", email)

	w.Header().Set("HX-Redirect", "/profile")
	w.WriteHeader(http.StatusOK)
	return
}

func (app *application) logout(w http.ResponseWriter, r *http.Request) {
	session, _ := app.cookieStore.Get(r, "auth-session")
	session.Options.MaxAge = -1
	session.Values = nil
	if err := session.Save(r, w); err != nil {
		app.serverError(w, r, err)
		return
	}

	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusSeeOther)
}

func (app *application) signupGet(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, http.StatusOK, "signup.html", templateData{})
}

func (app *application) signupPost(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	email := r.PostForm.Get("email")
	password := r.PostForm.Get("password")
	confirmPassword := r.PostForm.Get("confirm_password")

	if email == "" || password == "" {
		app.renderHTMXError(w, "Email and password are required")
		return
	}

	const minEntropyBits = 1
	err = passwordvalidator.Validate(password, minEntropyBits)
	if err != nil {
		app.errorLog.Println(err.Error())
		app.renderHTMXError(w, err.Error())
		return
	}

	if password != confirmPassword {
		app.renderHTMXError(w, "Passwords do not match")
		return
	}

	userId, err := app.users.Create(email, password)
	if err != nil {
		app.errorLog.Println(err.Error())
		var msg = "Failed to create account"
		if errors.Is(err, models.ErrDuplicateEmail) {
			msg = "An user with this email already exists"
		}

		app.renderHTMXError(w, msg)
		return
	}

	token, err := app.tokens.CreateEmailVerificationToken(userId)
	if err != nil {
		app.errorLog.Println(err.Error())
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

func (app *application) requestPasswdReset(w http.ResponseWriter, r *http.Request) {
	user := app.getAuthenticatedUser(r)
	token, err := app.tokens.CreatePasswordResetToken(user.ID)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	err = app.emailService.SendResetPasswordEmail(user.Email, app.config.BaseURL, token)
	if err != nil {
		app.errorLog.Println(err.Error())
		app.renderHTMXError(w, "Failed to send password reset email. Try again later.")
		return
	}

	app.renderHTMXSuccess(w, "Password reset requested. Check your email for the reset link.")
	return
}

func (app *application) verify(w http.ResponseWriter, r *http.Request) {
	data := templateData{}

	token := r.URL.Query().Get("token")
	if token == "" {
		data.Error = "Verification link is invalid. Try requesting a new verification link after logging in"
		app.render(w, r, http.StatusBadRequest, "signup.html", data)
		return
	}

	// TODO: this proccess should be atomic
	userID, err := app.tokens.Consume(models.EmailVerifyPurpose, token)
	if err != nil {
		app.errorLog.Println(err.Error())
		data.Error = "Token has already been used or is expired. Please request a new verification link after logging in"
		app.render(w, r, http.StatusBadRequest, "signup.html", data)
		return
	}

	err = app.users.VerifyEmailByID(userID)
	if err != nil {
		app.errorLog.Println(err.Error())
		data.Error = "Something went wrong. Please try again later"
		app.errorLog.Println("verify: failed to verify user email:", err)
		app.render(w, r, http.StatusBadRequest, "signup.html", data)
		return
	}

	app.infoLog.Printf("Email verified for user User %d", userID)
	app.render(w, r, http.StatusOK, "signup.html", data)

	// TODO: check what happens in this case
	email, err := app.users.GetEmailByID(userID)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	err = app.emailService.SendAccountVerifiedEmail(email)
	if err != nil {
		app.errorLog.Println("Failed send verification email to " + email + err.Error())
	}
}
