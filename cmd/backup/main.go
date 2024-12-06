package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/urfave/cli/v2"
	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"golang.org/x/term"
	"google.golang.org/protobuf/proto"
)

func main() {
	app := cli.App{
		Name:  "backup",
		Usage: "a tool to look into the backup files",
		Commands: []*cli.Command{
			{
				Name:   "show",
				Usage:  "show the contents of the backup file",
				Action: shhowBackup,
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:       "files",
						Usage:      "path to key share files",
						Required:   true,
						HasBeenSet: false,
					},
				},
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

func shhowBackup(c *cli.Context) error {
	files := c.StringSlice("files")
	if len(files) == 0 {
		return cli.Exit("no files provided", 1)
	}
	for _, file := range files {
		fmt.Println("File: ", file)
		if err := getLocalStateFromBak(file); err != nil {
			return cli.Exit(err, 1)
		}
	}
	return nil
}
func readFileContent(fi string) ([]byte, error) {
	return os.ReadFile(fi)
}

func getLocalStateFromBak(inputFileName string) error {
	filePathName, err := filepath.Abs(inputFileName)
	if err != nil {
		return fmt.Errorf("error getting absolute path for file %s: %w", inputFileName, err)
	}
	_, err = os.Stat(filePathName)
	if err != nil {
		return fmt.Errorf("error reading file %s: %w", inputFileName, err)
	}
	fileContent, err := readFileContent(filePathName)
	if err != nil {
		return fmt.Errorf("error reading file %s: %w", inputFileName, err)
	}

	rawContent, err := base64.StdEncoding.DecodeString(string(fileContent))
	if err != nil {
		return fmt.Errorf("error decoding file %s: %w", inputFileName, err)
	}
	var vaultContainer v1.VaultContainer
	if err := proto.Unmarshal(rawContent, &vaultContainer); err != nil {
		return fmt.Errorf("error unmarshalling file %s: %w", inputFileName, err)
	}
	var decryptedVault *v1.Vault
	// file is encrypted
	if vaultContainer.IsEncrypted {
		decryptedVault, err = decryptVault(&vaultContainer, inputFileName)
		if err != nil {
			return fmt.Errorf("error decrypting file %s: %w", inputFileName, err)
		}

	} else {
		vaultData, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
		if err != nil {
			return fmt.Errorf("failed to decode vault: %w", err)
		}
		var v v1.Vault
		if err := proto.Unmarshal(vaultData, &v); err != nil {
			return fmt.Errorf("failed to unmarshal vault: %w", err)

		}
		decryptedVault = &v
	}
	result, err := json.MarshalIndent(decryptedVault, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshalling file %s: %w", inputFileName, err)
	}
	fmt.Println(string(result))
	return nil
}
func decryptVault(vaultContainer *v1.VaultContainer, inputFileName string) (*v1.Vault, error) {
	vaultData, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
	if err != nil {
		return nil, fmt.Errorf("failed to decode vault: %w", err)
	}
	fmt.Printf("Enter password to decrypt the vault(%s): ", inputFileName)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	password := string(bytePassword)
	decryptedVault, err := gcmDecryptVault(password, vaultData)
	if err != nil {
		return nil, fmt.Errorf("error decrypting file %s: %w", inputFileName, err)
	}
	var vault v1.Vault
	if err := proto.Unmarshal(decryptedVault, &vault); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vault: %w", err)
	}
	return &vault, nil
}

func gcmDecryptVault(password string, vault []byte) ([]byte, error) {
	// Hash the password to create a key
	hash := sha256.Sum256([]byte(password))
	key := hash[:]

	// Create a new AES cipher using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Use GCM (Galois/Counter Mode)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Get the nonce size
	nonceSize := gcm.NonceSize()
	if len(vault) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract the nonce from the vault
	nonce, ciphertext := vault[:nonceSize], vault[nonceSize:]

	// Decrypt the vault
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
