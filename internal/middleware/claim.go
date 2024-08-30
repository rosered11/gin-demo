package middleware

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

const (
	claimKey      = "claim"
	userKey       = "user"
	tokenClaimKey = "X"
)

type MyClaim struct {
	Username string
	Code     string
}

var pemByteEnv []byte

func DecryptClaimToken(c *gin.Context) bool {
	tokenString := getClaimToken(c)

	if len(pemByteEnv) == 0 {
		base64Pem := os.Getenv("PEM")
		decodePem, _ := base64.StdEncoding.DecodeString(base64Pem)
		pemByteEnv = []byte(decodePem)
	}

	// Decode the PEM block
	block, _ := pem.Decode(pemByteEnv)
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatalf("Failed to decode PEM block containing public key")
	}

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse public key: %v", err)
	}

	// Assert the type of the key to *rsa.PublicKey
	rsaPublicKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		log.Fatalf("Not an RSA public key")
	}

	// Validate JWT Token
	claims := jwt.MapClaims{}
	jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return rsaPublicKey, nil
	})
	myClaim, err := setClaim(claims)
	if err != nil {
		return false
	}
	c.Set(claimKey, *myClaim)
	c.Set(userKey, &myClaim.Username)
	return true
}

func GetClaim(c *gin.Context) (*MyClaim, error) {
	v, ok := c.Get(claimKey)
	if !ok {
		return nil, errors.New("claim is empty")
	}
	myClaim, ok := v.(MyClaim)
	if !ok {
		return nil, errors.New("claim is empty")
	}
	return &myClaim, nil
}

func getClaimToken(c *gin.Context) string {
	return c.GetHeader(tokenClaimKey)
}

func setClaim(claims jwt.MapClaims) (*MyClaim, error) {
	payload, ok := claims["payload"].(map[string]interface{})
	if !ok {
		return nil, errors.New("payload is empty")
	}
	policies, ok := payload["policy"].([]interface{})
	if !ok || len(policies) == 0 {
		return nil, errors.New("policy is empty")
	}
	policy, ok := policies[0].(map[string]interface{})
	if !ok {
		return nil, errors.New("policy is empty")
	}
	code, ok := policy["code"].(string)
	if !ok {
		return nil, errors.New("code is empty")
	}
	user, ok := payload["user"].(map[string]interface{})
	if !ok {
		return nil, errors.New("user is empty")
	}
	uname, ok := user["uname"].(string)
	if !ok {
		return nil, errors.New("uname is empty")
	}
	username := strings.Split(uname, "@")
	if len(username) <= 0 {
		return nil, errors.New("username is empty")
	}
	myClaim := MyClaim{
		Username: username[0],
		Code:     code,
	}
	return &myClaim, nil
}
