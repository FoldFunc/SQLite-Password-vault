package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB
var JWTSECRET []byte

// User model
type Users struct {
	ID             uint   `gorm:"primaryKey"`
	Login          string `gorm:"unique;not null"`
	Password       string `gorm:"not null"`
	EncryptionSalt string `gorm:"not null"`
}

// Load environment variables
func InitEnv() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file: ", err)
	}
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET is not set in .env")
	}
	JWTSECRET = []byte(secret)
}

// Initialize DB and models
func Init() {
	var err error
	DB, err = gorm.Open(sqlite.Open("vault.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to the database: ", err)
	}
	if err := DB.AutoMigrate(&Users{}); err != nil {
		log.Fatal("AutoMigrate error: ", err)
	}
}

// --- Crypto Helpers ---

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func deriveKey(password string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
}

func encrypt(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(ciphertextBase64 string, key []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("cipher too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// --- API Structs and Handlers ---

type registerStruct struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func registerHandler(c *fiber.Ctx) error {
	var cred registerStruct
	if err := c.BodyParser(&cred); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if cred.Login == "" || cred.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing login or password"})
	}

	// Generate salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate salt"})
	}

	hashedPassword, err := HashPassword(cred.Password)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not hash password"})
	}

	user := Users{
		Login:          cred.Login,
		Password:       hashedPassword,
		EncryptionSalt: base64.StdEncoding.EncodeToString(salt),
	}

	if err := DB.Create(&user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not create user"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "User registered"})
}

type loginCredentials struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func loginHandler(c *fiber.Ctx) error {
	var cred loginCredentials
	if err := c.BodyParser(&cred); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	var user Users
	if err := DB.Where("login = ?", cred.Login).First(&user).Error; err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	if !CheckPasswordHash(cred.Password, user.Password) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	// Create JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"login": cred.Login,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(JWTSECRET)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not sign token"})
	}

	return c.JSON(fiber.Map{"token": tokenString})
}

// --- Main ---

func main() {
	InitEnv()
	Init()

	app := fiber.New()

	app.Post("/register", registerHandler)
	app.Post("/login", loginHandler)

	log.Fatal(app.Listen(":8080"))
}
