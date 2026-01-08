package main

import (
	_ "embed"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/mail"
	"owhyy/simple-auth/internal/models"
	"owhyy/simple-auth/ui/templates"
	"regexp"
	"strconv"
	"strings"
	"time"

	slug2 "github.com/gosimple/slug"
	passwordvalidator "github.com/wagslane/go-password-validator"
)

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]{3,20}$`)

func (app *application) home(w http.ResponseWriter, r *http.Request) {
	pagination, err := app.newPagination(r)
	if err != nil {
		app.serverError(w, r, err)
		return
	}
	total, err := app.posts.CountPublished()
	if err != nil {
		app.serverError(w, r, err)
		return
	}
	if total < pagination.PerPage {
		total = pagination.PerPage
	}
	pagination.TotalPages = total / pagination.PerPage

	posts, err := app.posts.GetPublished(pagination.PerPage, pagination.CurrentPage)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	app.render(w, r, http.StatusOK, "Home", templates.Home(posts, *pagination))
}

func (app *application) profile(w http.ResponseWriter, r *http.Request) {
	user := app.getAuthenticatedUser(r)
	app.render(w, r, http.StatusOK, "Profile", templates.Profile(*user))
}

func (app *application) loginGet(w http.ResponseWriter, r *http.Request) {
	if app.isAuthenticated(r) {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	app.render(w, r, http.StatusOK, "Login", templates.Login())
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
		app.clientError(w, http.StatusBadRequest)
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
	app.render(w, r, http.StatusOK, "Sign up", templates.Signup())
}

func (app *application) signupPost(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	username := r.PostForm.Get("username")
	email := r.PostForm.Get("email")
	password := r.PostForm.Get("password")
	confirmPassword := r.PostForm.Get("confirm_password")

	if username == "" || email == "" || password == "" {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	if !usernameRegex.MatchString(username) {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	_, err = mail.ParseAddress(email)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	const minEntropyBits = 50
	err = passwordvalidator.Validate(password, minEntropyBits)
	if err != nil {
		fmt.Fprintf(w, `
            <label for="password" id="password-input" hx-swap-oob="true" x-data="{ error: true }">
                Password
                <input id="password" minlength="8" name="password" required type="password" :aria-invalid="error" @input="error = false">
            </label>

            <label for="confirm-password" id="confirm-password-input" hx-swap-oob="true" x-data="{ error: true }">
                Confirm Password
                <input id="confirm-password" minlength="8" name="confirm_password" required type="password" :aria-invalid="error" @input="error = false">
                <small x-show="error">Error: %s</small>
            </label>
`, err.Error())
		return
	}

	if password != confirmPassword {
		w.Write([]byte(`
            <label for="password" id="password-input" hx-swap-oob="true" x-data="{error: true}">
                Password
                <input id="password" minlength="8" name="password" required type="password" :aria-invalid="error" @input="error = false">
            </label>

            <label for="confirm-password" id="confirm-password-input" hx-swap-oob="true" x-data="{ error: true }">
                Confirm Password
                <input id="confirm-password" minlength="8" name="confirm_password" required type="password" @input="error = false" :aria-invalid="error">
                <small x-show="error">Passwords must match</small>
            </label>
`))
		return
	}

	userId, err := app.users.Create(email, username, password)
	if err != nil {
		if errors.Is(err, models.ErrDuplicateEmail) {
			fmt.Fprintf(w, `
            <label id="email-input" for="email" hx-swap-oob="true" x-data="{ error: true }">
                Email
                <input id="email" name="email" required type="email" :aria-invalid="error" value="%s" @input="error = false">
                <small x-show="error">An user with this email already exists</small>
            </label>`, html.EscapeString(email))
			return
		}

		if errors.Is(err, models.ErrDuplicateUsername) {
			fmt.Fprintf(w, `
            <label id="username-input" for="username" hx-swap-oob="true" x-data="{ error: true }">
                Username
                <input id="username" name="username" required minlength="3" maxlength="20" type="text" pattern="^[a-zA-Z0-9_]{3,20}$" title="Only letters, numbers and underscores allowed" value="%s" :aria-invalid="error"@input="error = false" >
                <small x-show="error">An user with this username already exists</small>		
            </label>`, html.EscapeString(username))
			return
		}

		app.clientError(w, http.StatusBadRequest)
		return
	}

	token, err := app.tokens.CreateEmailVerificationToken(userId)
	if err != nil {
		app.errorLog.Println(err.Error())
	}
	app.infoLog.Println("Token " + token + " created for " + email)
	err = app.emailService.SendVerificationEmail(email, app.config.BaseURL, token)
	// Should we display error to front-end or not?
	// In a real-world app, we'd probably log this and
	// retry without the user knowing about it
	if err != nil {
		app.errorLog.Printf("Failed to send verification email to %s. Error %s", email, err.Error())
	}

	w.Header().Set("HX-Redirect", "/login")
	w.WriteHeader(http.StatusOK)
}

func (app *application) requestPasswdResetGet(w http.ResponseWriter, r *http.Request) {
	if app.isAuthenticated(r) {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	app.render(w, r, http.StatusOK, "Forgot password", templates.ForgotPassword())
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

	err = app.emailService.SendResetPasswordEmail(user.Email, app.config.BaseURL, token)
	if err != nil {
		app.errorLog.Println(err.Error())
		return
	}
}

func (app *application) resetPasswordGet(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		errMsg := "Verification link is invalid. Try requesting a new password reset"
		app.render(w, r, http.StatusBadRequest, "Reset your password", templates.PasswordReset(errMsg, ""))
		return
	}

	exists, err := app.tokens.ExistsValid(models.PasswordResetPurpose, token)
	if err != nil {
		app.serverError(w, r, err)
		return
	}
	if !exists {
		errMsg := "Token has already been used or is expired. Try requesting a new password reset"
		app.render(w, r, http.StatusBadRequest, "Reset your password", templates.PasswordReset(errMsg, ""))
		return
	}

	app.render(w, r, http.StatusOK, "Reset your password", templates.PasswordReset("", token))
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
	token := r.URL.Query().Get("token")
	if token == "" {
		errMsg := "Verification link is invalid. Try requesting a new verification link after logging in"
		app.render(w, r, http.StatusBadRequest, "Verify your email", templates.Verify(errMsg))
		return
	}

	// TODO: this proccess should be atomic
	userID, err := app.tokens.Consume(models.EmailVerifyPurpose, token)
	if err != nil {
		app.errorLog.Println(err.Error())
		errMsg := "Token has already been used or is expired. Please request a new verification link after logging in"
		app.render(w, r, http.StatusBadRequest, "Verify your email", templates.Verify(errMsg))
		return
	}

	err = app.users.VerifyEmailByID(userID)
	if err != nil {
		app.errorLog.Println(err.Error())
		errMsg := "Something went wrong. Please try again later"
		app.errorLog.Println("verify: failed to verify user email:", err)
		app.render(w, r, http.StatusBadRequest, "Verify your email", templates.Verify(errMsg))
		return
	}

	app.infoLog.Printf("Email verified for user User %d", userID)
	app.render(w, r, http.StatusOK, "Verify your email", templates.Verify(""))

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

func (app *application) viewPost(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/posts/view/")
	if slug == "" {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	post, err := app.posts.GetBySlug(slug)
	if err != nil {
		if errors.Is(err, models.ErrRecordNotFound) {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		app.serverError(w, r, err)
		return
	}

	user := app.getAuthenticatedUser(r)
	if post.Status == models.Draft && (!app.isAuthenticated(r) || user == nil || (post.AuthorID != user.ID && !user.IsAdmin)) {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	app.render(w, r, http.StatusOK, post.Title, templates.PostView(*post, app.isAuthenticated(r), user))
}

func (app *application) publishPost(w http.ResponseWriter, r *http.Request) {
	user := app.getAuthenticatedUser(r)
	if user == nil {
		app.clientError(w, http.StatusUnauthorized)
		return
	}

	idStr := r.PathValue("id")
	postID, err := strconv.Atoi(idStr)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	post, err := app.posts.GetByID(uint(postID))
	if err != nil {
		if errors.Is(err, models.ErrRecordNotFound) {
			app.clientError(w, http.StatusNotFound)
			return
		}
		app.serverError(w, r, err)
		return
	}

	if post.AuthorID != user.ID && !user.IsAdmin {
		app.clientError(w, http.StatusForbidden)
		return
	}

	if post.Status == models.Published {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	now := time.Now()
	err = app.posts.UpdateStatus(uint(postID), models.Published, &now)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	updatedPost, err := app.posts.GetByID(uint(postID))
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	templates.PostView(*updatedPost, true, user).Render(r.Context(), w)
}

func (app *application) unpublishPost(w http.ResponseWriter, r *http.Request) {
	user := app.getAuthenticatedUser(r)
	if user == nil {
		app.clientError(w, http.StatusUnauthorized)
		return
	}

	idStr := r.PathValue("id")
	postID, err := strconv.Atoi(idStr)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	post, err := app.posts.GetByID(uint(postID))
	if err != nil {
		if errors.Is(err, models.ErrRecordNotFound) {
			app.clientError(w, http.StatusNotFound)
			return
		}
		app.serverError(w, r, err)
		return
	}

	if post.AuthorID != user.ID && !user.IsAdmin {
		app.clientError(w, http.StatusForbidden)
		return
	}

	if post.Status == models.Draft {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	err = app.posts.UpdateStatus(uint(postID), models.Draft, nil)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	updatedPost, err := app.posts.GetByID(uint(postID))
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	templates.PostView(*updatedPost, true, user).Render(r.Context(), w)
}

func (app *application) updatePost(w http.ResponseWriter, r *http.Request) {
	user := app.getAuthenticatedUser(r)
	if user == nil {
		app.clientError(w, http.StatusUnauthorized)
		return
	}

	idStr := r.PathValue("id")
	postID, err := strconv.Atoi(idStr)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	post, err := app.posts.GetByID(uint(postID))
	if err != nil {
		if errors.Is(err, models.ErrRecordNotFound) {
			app.clientError(w, http.StatusNotFound)
			return
		}
		app.serverError(w, r, err)
		return
	}

	if post.AuthorID != user.ID && !user.IsAdmin {
		app.clientError(w, http.StatusForbidden)
		return
	}

	err = r.ParseForm()
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	title := r.PostForm.Get("title")
	content := r.PostForm.Get("content")

	if title == "" {
		title = post.Title
	}
	if content == "" {
		content = post.Content
	}

	err = app.posts.Update(uint(postID), title, content)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	updatedPost, err := app.posts.GetByID(uint(postID))
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	templates.PostView(*updatedPost, true, user).Render(r.Context(), w)
}

func (app *application) deletePost(w http.ResponseWriter, r *http.Request) {
	user := app.getAuthenticatedUser(r)
	if user == nil {
		app.clientError(w, http.StatusUnauthorized)
		return
	}

	idStr := r.PathValue("id")
	postID, err := strconv.Atoi(idStr)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	post, err := app.posts.GetByID(uint(postID))
	if err != nil {
		if errors.Is(err, models.ErrRecordNotFound) {
			app.clientError(w, http.StatusNotFound)
			return
		}
		app.serverError(w, r, err)
		return
	}

	if post.AuthorID != user.ID && !user.IsAdmin {
		app.clientError(w, http.StatusForbidden)
		return
	}

	err = app.posts.Delete(uint(postID))
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusOK)
}

func (app *application) postCreateGet(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, http.StatusOK, "New Post", templates.PostCreate())
}

func (app *application) postCreatePost(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	title := r.PostForm.Get("title")
	excerpt := r.PostForm.Get("excerpt")
	content := r.PostForm.Get("content")
	statusStr := r.PostForm.Get("status")

	if title == "" || content == "" || statusStr == "" {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	if excerpt == "" {
		excerpt = content
		if len(excerpt) > 150 {
			excerpt = excerpt[:150]
		}
	}

	var published_at *time.Time
	status := models.PostStatus(statusStr)
	if status == models.Published {
		t := time.Now()
		published_at = &t
	}

	author := app.getAuthenticatedUser(r)

	slug := slug2.Make(title)
	slug_cnt, err := app.posts.CountSlugs(slug)
	slug = fmt.Sprintf("%s-%d", slug, slug_cnt+1)

	if err != nil {
		app.serverError(w, r, err)
		return
	}

	post := &models.Post{
		Title:         title,
		Slug:          slug,
		Content:       content,
		Excerpt:       excerpt,
		AuthorID:      author.ID,
		Status:        status,
		PublishedAt:   published_at,
		FeaturedImage: nil,
	}

	err = app.posts.Create(post)
	if err != nil {
		app.errorLog.Println(err)
		app.clientError(w, http.StatusBadRequest)
		return
	}

	w.Header().Set("HX-Redirect", "/posts/view/"+slug)
	w.WriteHeader(http.StatusOK)
}

func (app *application) myPosts(w http.ResponseWriter, r *http.Request) {
	pagination, err := app.newPagination(r)
	if err != nil {
		app.serverError(w, r, err)
		return
	}
	user := app.getAuthenticatedUser(r)
	total, err := app.posts.CountForUser(user.ID)
	if err != nil {
		app.serverError(w, r, err)
		return
	}
	if total < pagination.PerPage {
		total = pagination.PerPage
	}
	pagination.TotalPages = total / pagination.PerPage

	posts, err := app.posts.GetByAuthorID(user.ID, pagination.PerPage, pagination.CurrentPage)
	if err != nil {
		app.serverError(w, r, err)
		return
	}
	app.render(w, r, http.StatusOK, "My posts", templates.MyPosts(posts, *pagination))
}
