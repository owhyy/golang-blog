package services

import (
	"fmt"
	"net/smtp"
)

type EmailService struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

func (s *EmailService) SendEmail(to, subject, body string) error {
	msg := []byte(
		"From: " + s.From + "\r\n" +
			"To: " + to + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-version: 1.0;\r\n" +
			"Content-Type: text/html; charset=\"UTF-8\";\r\n" +
			"\r\n" +
			body + "\r\n")
	auth := smtp.PlainAuth("", s.Username, s.Password, s.Host)
	return smtp.SendMail(
		s.Host+":"+s.Port,
		auth,
		s.From,
		[]string{to},
		msg,
	)
}

func (s *EmailService) SendVerificationEmail(to, baseURL, token string) error {
	verifyURL := fmt.Sprintf("%s/verify?token=%s", baseURL, token)
	subject := "Verify your email address"
	body := fmt.Sprintf(`
		<html>
		<body>
			<h2>Welcome!</h2>
			<p>Please verify your email address by clicking the link below:</p>
			<p><a href="%s">Verify Email</a></p>
			<p>This link will expire in 30 minutes.</p>
			<p>If you didn't sign up, please ignore this email.</p>
		</body>
		</html>
	`, verifyURL)

	return s.SendEmail(to, subject, body)
}

func (s *EmailService) SendAccountVerifiedEmail(to string) error {
	subject := "Email verified successfully"
	body := `
		<html>
		<body>
			<h2>Hi!</h2>
			<p>Welcome aboard!</p>
			<p>Your email was verified successfully</p>
		</body>
		</html>
`
	return s.SendEmail(to, subject, body)
}

func (s *EmailService) SendResetPasswordEmail(to, baseURL, token string) error {
	verifyURL := fmt.Sprintf("%s/reset-password?token=%s", baseURL, token)
	subject := "Reset Password"
	body := fmt.Sprintf(`
		<html>
		<body>
			<h2>Password reset</h2>
			<p>You can reset your password by clicking the link below:</p>
			<p><a href="%s">Reset Password</a></p>
			<p>This link will expire in 10 minutes.</p>
			<p>If you didn't request a password reset, please ignore this email.</p>
		</body>
		</html>
	`, verifyURL)

	return s.SendEmail(to, subject, body)
}
