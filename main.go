package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

type Account struct {
	ID             uint   `gorm:"primaryKey"`
	Login          string `gorm:"unique;not null"`
	Password       string `gorm:"not null"`
	EncryptionSalt string `gorm:"not null"`
}

type Entry struct {
	ID          uint   `gorm:"primaryKey"`
	AccountID   uint   `gorm:"not null"`
	Information string `gorm:"not null"`
}

func Init() {
	var err error
	DB, err = gorm.Open(sqlite.Open("vault.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	if err := DB.AutoMigrate(&Account{}, &Entry{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func ReadInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("Error reading input: %v", err)
	}
	return strings.TrimSpace(input)
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
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func main() {
	Init()

	hasAccount := ReadInput("Do you have an account? (yes/no): ")
	if strings.ToLower(hasAccount) == "yes" {
		vaultLogin := ReadInput("Enter your vault login: ")
		vaultPassword := ReadInput("Enter your vault password: ")

		var account Account
		result := DB.Where("login = ?", vaultLogin).First(&account)
		if result.Error != nil {
			log.Println("Invalid login or password")
			return
		}

		if !CheckPasswordHash(vaultPassword, account.Password) {
			log.Println("Invalid login or password")
			return
		}

		salt, err := base64.StdEncoding.DecodeString(account.EncryptionSalt)
		if err != nil {
			log.Fatalf("Failed to decode encryption salt: %v", err)
		}
		key, err := deriveKey(vaultPassword, salt)
		if err != nil {
			log.Fatalf("Failed to derive encryption key: %v", err)
		}

		fmt.Println("Welcome user:", account.Login)
		run := true
		for run {
			action := ReadInput("For now you can only (cve - create vault entry, sae - see all entries, exit). What would you like to do?: ")
			switch strings.ToLower(action) {
			case "cve":
				information := ReadInput("What would you like to store?: ")
				encryptedInfo, err := encrypt(information, key)
				if err != nil {
					log.Fatal("Error while encrypting the entry:", err)
				}
				entry := Entry{AccountID: account.ID, Information: encryptedInfo}
				if err := DB.Create(&entry).Error; err != nil {
					log.Println("Error while adding information to the vault:", err)
					return
				}
				fmt.Println("Information added to the database.")
			case "sae":
				var entries []Entry
				result := DB.Where("account_id = ?", account.ID).Find(&entries)
				if result.Error != nil {
					log.Println("Error retrieving entries:", result.Error)
					return
				}

				if len(entries) == 0 {
					fmt.Println("No entries found.")
					return
				}
				fmt.Println("Your entries:")
				for _, entry := range entries {
					decryptedInfo, err := decrypt(entry.Information, key)
					if err != nil {
						fmt.Printf("ID: %d, Error decrypting information\n", entry.ID)
						continue
					}
					fmt.Printf("ID: %d, Information: %s\n", entry.ID, decryptedInfo)
				}
			case "exit":
				run = false
			default:
				fmt.Println("Invalid option selected.")
			}
		}

	} else {
		newVaultLogin := ReadInput("Enter your new vault login: ")
		newVaultPassword := ReadInput("Enter your new vault password: ")

		hashedPassword, err := HashPassword(newVaultPassword)
		if err != nil {
			log.Println("Error while hashing password:", err)
			return
		}

		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			log.Fatalf("Failed to generate encryption salt: %v", err)
		}
		encodedSalt := base64.StdEncoding.EncodeToString(salt)

		account := Account{
			Login:          newVaultLogin,
			Password:       hashedPassword,
			EncryptionSalt: encodedSalt,
		}
		if err := DB.Create(&account).Error; err != nil {
			log.Println("Error while creating a user:", err)
			return
		}
		fmt.Println("Account successfully created.")
	}
}

// Test commit

