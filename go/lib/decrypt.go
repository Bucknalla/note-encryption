package lib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

type EncryptedPayload struct {
	Algorithm string `json:"alg"`
	Data      string `json:"data"`
	Env       string `json:"env"`
	Key       string `json:"key"`
}

func DecryptData(privateKeyPath string, payload EncryptedPayload) ([]byte, error) {
	// 1. Load private key
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %v", err)
	}

	// Parse PEM block
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	// Parse private key
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// 2. Decode ephemeral public key from base64
	publicKeyDER, err := base64.StdEncoding.DecodeString(payload.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %v", err)
	}

	// Parse public key
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	// 3. Create ECDH keys
	curve := ecdh.P384()

	privKey, err := curve.NewPrivateKey(privateKey.D.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDH private key: %v", err)
	}

	// Concatenate X and Y coordinates with 0x04 prefix (uncompressed point format)
	pubKeyBytes := append([]byte{0x04}, append(publicKey.(*ecdsa.PublicKey).X.Bytes(), publicKey.(*ecdsa.PublicKey).Y.Bytes()...)...)
	pubKey, err := curve.NewPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDH public key: %v", err)
	}

	// 4. Compute shared secret
	sharedSecret, err := privKey.ECDH(pubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %v", err)
	}

	// 5. Generate AES key by hashing shared secret
	hash := sha256.Sum256(sharedSecret)
	aesKey := hash[:]

	// 6. Decode encrypted data
	encryptedData, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %v", err)
	}

	// 7. Create AES cipher
	aesCipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// 8. Create CBC decrypter with zero IV
	iv := make([]byte, aes.BlockSize)
	mode := cipher.NewCBCDecrypter(aesCipher, iv)

	// 9. Decrypt data
	decrypted := make([]byte, len(encryptedData))
	mode.CryptBlocks(decrypted, encryptedData)

	// 10. Remove padding if present
	if len(decrypted) > 0 {
		paddingLen := int(decrypted[len(decrypted)-1])
		if paddingLen > 0 && paddingLen <= aes.BlockSize {
			decrypted = decrypted[:len(decrypted)-paddingLen]
		}
	}

	return decrypted, nil
}
