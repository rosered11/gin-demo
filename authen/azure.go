package authen

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

const (
	unAuthorized    = "Unauthorized"
	authType        = "Bearer"
	authorizeHeader = "Authorization"
)

type azureKeyType struct {
	N string
	E string
}

var rsaPublicKey *rsa.PublicKey

func Validate(c *gin.Context, envFile map[string]string) error {

	authHeader := c.GetHeader(authorizeHeader)
	if authHeader == "" {
		// c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return errors.New(unAuthorized)
	}

	tokenString := strings.TrimSpace(strings.TrimPrefix(authHeader, authType))

	if rsaPublicKey == nil {
		publicKey, err := prepareKeyAzure(envFile)
		if err != nil {
			return errors.New(unAuthorized)
		}
		rsaPublicKey = publicKey
	}

	// Parse and validate the JWT using the RSA public key
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return rsaPublicKey, nil
	})
	if err != nil {
		// c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return errors.New(unAuthorized)
	}

	if !token.Valid {
		// c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return errors.New(unAuthorized)
	}

	valid := DecryptClaimToken(c, envFile)
	if !valid {
		// c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return errors.New(unAuthorized)
	}
	return nil
}

func prepareKeyAzure(envFile map[string]string) (*rsa.PublicKey, error) {
	response, err := http.Get(
		fmt.Sprintf("%s/%s/%s/v2.0/.well-known/openid-configuration",
			envFile["AZURE_INSTANCE"], envFile["AZURE_DOMAIN"], envFile["AZURE_TENANT"]),
	)

	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}

	responseByteData, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	var responseData map[string]any
	if err := json.Unmarshal(responseByteData, &responseData); err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	jwtkUrl := responseData["jwks_uri"].(string)

	if jwtkUrl == "" {
		log.Fatal("jwtk url is empty")
	}

	response, err = http.Get(jwtkUrl)
	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}

	responseByteData, err = io.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	var responseDataJwks interface{}
	if err := json.Unmarshal(responseByteData, &responseDataJwks); err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}
	responseByteDataMap, ok := responseDataJwks.(map[string]interface{})
	if !ok {
		log.Fatal("jwks key is empty")
	}
	responseDatas := responseByteDataMap["keys"].([]interface{})
	if len(responseDatas) == 0 {
		log.Fatal("Azure AD process incomplete")
	}
	var azureKey *azureKeyType
	firstData, ok := responseDatas[0].(map[string]interface{})
	if ok && firstData["e"] != "" && firstData["n"] != "" {
		azureKey = &azureKeyType{
			N: firstData["n"].(string),
			E: firstData["e"].(string),
		}
	}

	// N
	nBytes, err := base64.RawURLEncoding.DecodeString(azureKey.N)
	if err != nil {
		// c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return nil, errors.New(unAuthorized)
	}
	// E
	eBytes, err := base64.RawURLEncoding.DecodeString(azureKey.E)
	if err != nil {
		// c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return nil, errors.New(unAuthorized)
	}

	n := big.NewInt(0)
	n.SetBytes(nBytes)

	e := int(big.NewInt(0).SetBytes(eBytes).Int64())

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}
