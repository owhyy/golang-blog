package main

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	SMTPHost     string
	SMTPPort     string	
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string

	BaseURL string
}

func LoadConfig() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	cfg := &Config{}

	cfg.SMTPHost = os.Getenv("SMTP_HOST")
	cfg.SMTPPort = os.Getenv("SMTP_PORT")	
	cfg.SMTPUsername = os.Getenv("SMTP_USERNAME")
	cfg.SMTPPassword = os.Getenv("SMTP_PASSWORD")
	cfg.SMTPFrom = os.Getenv("SMTP_FROM")
	cfg.BaseURL = os.Getenv("BASE_URL")
	return cfg, nil
}
