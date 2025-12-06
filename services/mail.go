package services

import (
	"fmt"
	"net/smtp"
)

type EmailService struct {
	host     string
	port     string
	username string
	password string
	from     string
}

func NewEmailService(host, port, username, password, from string) *EmailService {
	return &EmailService{
		host:     host,
		port:     port,
		username: username,
		password: password,
		from:     from,
	}
}

func (s *EmailService) SendEmail(to, subject, body string) error {
	msg := []byte(
		"From: " + s.from + "\r\n" +
			"To: " + to + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-version: 1.0;\r\n" +
			"Content-Type: text/html; charset=\"UTF-8\";\r\n" +
			"\r\n" +
			body + "\r\n")

	auth := smtp.PlainAuth("", s.username, s.password, s.host)

	err := smtp.SendMail(
		s.host+s.port,
		auth,
		s.from,
		[]string{to},
		msg,
	)

	return err
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
