package main

import (
	"encoding/json"
	"net/http"

	"github.com/Bucknalla/note-encryption/lib"
	"github.com/gin-gonic/gin"
)

type DecryptRequest struct {
	Algorithm string `json:"alg"`
	Data      string `json:"data"`
	Env       string `json:"env"`
	Key       string `json:"key"`
}

func main() {
	r := gin.Default()

	r.POST("/decrypt", func(c *gin.Context) {
		var request DecryptRequest
		if err := c.BindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		payload := lib.EncryptedPayload{
			Algorithm: request.Algorithm,
			Data:      request.Data,
			Env:       request.Env,
			Key:       request.Key,
		}

		decrypted, err := lib.DecryptData("../keys/privateKey.pem", payload)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var jsonData interface{}
		if err := json.Unmarshal(decrypted, &jsonData); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse decrypted JSON"})
			return
		}

		c.JSON(http.StatusOK, jsonData)
	})

	r.Run(":4000")
}
