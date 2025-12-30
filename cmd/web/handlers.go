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
	app.render(w, r, http.StatusOK, "home.html", app.newTemplateData(r))
}

func (app *application) profile(w http.ResponseWriter, r *http.Request) {
	user := app.getAuthenticatedUser(r)
	data := app.newTemplateData(r)
	data.User = *user
	app.render(w, r, http.StatusOK, "profile.html", data)
}

func (app *application) loginGet(w http.ResponseWriter, r *http.Request) {
	if app.isAuthenticated(r) {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	app.render(w, r, http.StatusOK, "login.html", app.newTemplateData(r))
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
	app.render(w, r, http.StatusOK, "signup.html", app.newTemplateData(r))
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

func (app *application) requestPasswdResetGet(w http.ResponseWriter, r *http.Request) {
	if app.isAuthenticated(r) {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	app.render(w, r, http.StatusOK, "forgot_password.html", templateData{})
}

func (app *application) requestPasswdResetPost(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	email := r.PostForm.Get("email")
	app.infoLog.Println(email)
	app.infoLog.Println(r.PostForm)
	user, err := app.users.GetByEmail(email)
	w.Write([]byte(`
	<hgroup>
		<h1>Check your inbox</h1>
		<p>You will soon receive an email containing password reset instructions</p>
	</hgroup>
		<a class="primary" href="/" role="button">Go back</a>
`))

	if err != nil {
		app.errorLog.Println(err.Error())
		return
	}

	canRequestReset, err := app.users.CanCreatePasswordRequest(user.ID)
	if err != nil {
		app.errorLog.Println(err.Error())
		return
	}
	if !canRequestReset {
		app.errorLog.Println("Too many password reset requests for " + email)
		return
	}

	token, err := app.tokens.CreatePasswordResetToken(user.ID)
	if err != nil {
		app.errorLog.Println(err.Error())
		return
	}

	// This should be done asynchronously, because
	// right now it is possible to tell if an email exists
	// or not by looking at how long the request takes
	err = app.emailService.SendResetPasswordEmail(user.Email, app.config.BaseURL, token)
	if err != nil {
		app.errorLog.Println(err.Error())
		return
	}
}

func (app *application) resetPasswordGet(w http.ResponseWriter, r *http.Request) {
	data := app.newTemplateData(r)
	token := r.URL.Query().Get("token")
	if token == "" {
		data.Error = "Verification link is invalid. Try requesting a new password reset"
		app.render(w, r, http.StatusBadRequest, "password_reset.html", data)
		return
	}

	exists, err := app.tokens.ExistsValid(models.PasswordResetPurpose, token)
	if err != nil {
		app.serverError(w, r, err)
		return
	}
	if !exists {
		data.Error = "Token has already been used or is expired. Try requesting a new password reset"
		app.render(w, r, http.StatusBadRequest, "password_reset.html", data)
		return
	}

	data.Token = token
	app.render(w, r, http.StatusOK, "password_reset.html", data)
}

func (app *application) resetPasswordPost(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		app.errorLog.Println(err.Error())
		app.clientError(w, http.StatusBadRequest)
		return
	}

	token := r.PostForm.Get("token")
	password := r.PostForm.Get("password")
	passwordConfirm := r.PostForm.Get("confirm_password")
	if token == "" || password == "" || passwordConfirm == "" {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	// Only case where we have to show error to the UI
	// because it can happen because of the user.
	// All other errors should not normally happen
	// so it's safe to return them as API errors
	if password != passwordConfirm {
		app.renderHTMXError(w, "Passwords do not match")
		return
	}

	userID, err := app.tokens.Consume(models.PasswordResetPurpose, token)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	err = app.users.SetPassword(userID, password)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	w.Write([]byte(`<div id="main" hx-swap-oob=true>
            <h1>Password updated successfully ✅</h1>
            <p>Your password has been successfully changed. You can proceed to log in.</p>
            <a href="/login" role="button">Go to login</a></div>`))
}

func (app *application) verify(w http.ResponseWriter, r *http.Request) {
	data := app.newTemplateData(r)

	token := r.URL.Query().Get("token")
	if token == "" {
		data.Error = "Verification link is invalid. Try requesting a new verification link after logging in"
		app.render(w, r, http.StatusBadRequest, "verify.html", data)
		return
	}

	// TODO: this proccess should be atomic
	userID, err := app.tokens.Consume(models.EmailVerifyPurpose, token)
	if err != nil {
		app.errorLog.Println(err.Error())
		data.Error = "Token has already been used or is expired. Please request a new verification link after logging in"
		app.render(w, r, http.StatusBadRequest, "verify.html", data)
		return
	}

	err = app.users.VerifyEmailByID(userID)
	if err != nil {
		app.errorLog.Println(err.Error())
		data.Error = "Something went wrong. Please try again later"
		app.errorLog.Println("verify: failed to verify user email:", err)
		app.render(w, r, http.StatusBadRequest, "verify.html", data)
		return
	}

	app.infoLog.Printf("Email verified for user User %d", userID)
	app.render(w, r, http.StatusOK, "verify.html", data)

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
