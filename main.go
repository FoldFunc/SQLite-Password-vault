package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"io"
	"log"
	"os"
	"time"
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

type vaultInfo struct {
	ID        uint   `gorm:"primaryKey"`
	UserEmail string `gorm:" not null"`
	Title     string `json:"title"`
	Secret    string `json:"secret"`
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
	if err := DB.AutoMigrate(&Users{}, &vaultInfo{}); err != nil {
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
	log.Println("loginHandler called")
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
		"email": cred.Login,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(JWTSECRET)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not sign token"})
	}
	c.Cookie(&fiber.Cookie{
		Name:     "token",
		Value:    tokenString,
		HTTPOnly: true,
		Secure:   false,
		SameSite: "Lax",
	})

	return c.JSON(fiber.Map{"token": tokenString})
}

func jwtMiddleware(c *fiber.Ctx) error {
	tokenString := c.Cookies("token")
	if tokenString == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Missing token"})
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return JWTSECRET, nil
	})
	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
	}

	claims := token.Claims.(jwt.MapClaims)
	c.Locals("user", claims["email"])
	return c.Next()
}

func makeVaultEntryHandler(c *fiber.Ctx) error {
	log.Println("makeVaultEntryHandler called")

	// Get the token from the cookie
	tokenString := c.Cookies("token")
	if tokenString == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Missing token"})
	}

	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return JWTSECRET, nil
	})
	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
	}

	// Extract claims
	claims := token.Claims.(jwt.MapClaims)
	login, ok := claims["email"].(string)
	if !ok || login == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token: email missing"})
	}

	// Find user
	var user Users
	if err := DB.Where("login = ?", login).First(&user).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	// Parse body
	var input vaultInfo
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid body"})
	}

	// Ensure Title and Secret are provided
	if input.Title == "" || input.Secret == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing title or secret"})
	}

	// Encrypt the secret before saving it
	salt, _ := base64.StdEncoding.DecodeString(user.EncryptionSalt)
	key, _ := deriveKey(user.Password, salt)

	encryptedSecret, err := encrypt(input.Secret, key)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Encryption failed"})
	}

	entry := vaultInfo{
		UserEmail: login,
		Title:     input.Title,
		Secret:    encryptedSecret,
	}

	if err := DB.Create(&entry).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not save entry"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "Vault entry added"})
}

func getVaultEntryHandler(c *fiber.Ctx) error {
	// Get the token from the cookie
	tokenString := c.Cookies("token")
	if tokenString == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Missing token"})
	}

	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return JWTSECRET, nil
	})
	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
	}

	// Extract claims and verify email exists
	claims := token.Claims.(jwt.MapClaims)
	login, ok := claims["email"].(string)
	if !ok || login == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token: email missing"})
	}

	// Get user record to derive decryption key
	var user Users
	if err := DB.Where("login = ?", login).First(&user).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	// Query for vault entry. You might want to search by title or other criteria.
	var entry vaultInfo
	if err := DB.Where("user_email = ?", login).First(&entry).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Entry not found"})
	}

	// Decrypt the secret before sending it in the response
	salt, _ := base64.StdEncoding.DecodeString(user.EncryptionSalt)
	key, _ := deriveKey(user.Password, salt)
	decryptedSecret, err := decrypt(entry.Secret, key)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not decrypt secret"})
	}

	// Return a response with the decrypted secret (plain-text)
	response := fiber.Map{
		"ID":        entry.ID,
		"UserEmail": entry.UserEmail,
		"title":     entry.Title,
		"secret":    decryptedSecret,
	}

	return c.JSON(response)
}

func main() {
	InitEnv()
	Init()

	app := fiber.New()

	// Use CORS middleware to allow cross-origin requests
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000",                       // Allow the frontend app to connect
		AllowMethods:     "GET,POST,PUT,DELETE",                         // Allow these HTTP methods
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization", // Allow these headers
		AllowCredentials: true,
	}))

	app.Use(limiter.New())
	app.Post("/register", registerHandler)
	app.Post("/login", loginHandler)
	app.Post("/makeVaultEntry", makeVaultEntryHandler)
	app.Post("/getVaultEntry", getVaultEntryHandler)

	log.Fatal(app.Listen(":8080"))
}

