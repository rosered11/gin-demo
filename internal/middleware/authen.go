package middleware

import (
	"fmt"
	"gindemo/internal/apierror"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/rs/zerolog/log"
)

type AuthenticatorConfig struct {
	KeySetJSON []byte
	Issuer     string
}

const (
	authType = "Bearer"
)

func Authenticator(keySet jwk.Set) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Ignore the root as it is used for the liveness probes
		if c.Request.URL.Path == "/" {
			return
		}

		// Gets the JWT from the Authentication header
		authHeader := strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), authType))
		if authHeader == "" {
			log.Debug().Msg("JWT not found")
			c.AbortWithStatusJSON(
				http.StatusUnauthorized,
				apierror.New("Not authorized"))
			return
		}
		msg, err := jws.Parse([]byte(authHeader))
		if err != nil {
			return
		}
		header := msg.Signatures()[0].ProtectedHeaders()
		key, _ := keySet.LookupKeyID(header.KeyID())

		// Validates the JWT
		_, err = validateToken(key, authHeader)
		if err != nil {
			log.Debug().Err(err).Msg("JWT not valid")
			c.AbortWithStatusJSON(
				http.StatusUnauthorized,
				apierror.New("Not authorized"))
			return
		}
		valid := DecryptClaimToken(c)
		if !valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
	}
}

func validateToken(key jwk.Key, tokenString string) (jwt.Token, error) {
	// Step 1: Confirm the structure of the JWT
	// Step 2: Validate the JWT signature
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithJwtID(key.KeyID()),
	)
	jwt.Parse([]byte(tokenString))
	if err != nil {
		log.Debug().Err(err).Msg("error parsing the token")
		return nil, fmt.Errorf("invalid token: %s", err)
	}

	// Step 3: Verify the claims
	err = jwt.Validate(token, jwt.WithClaimValue(jwt.IssuerKey, token.Issuer()))
	if err != nil {
		log.Debug().Err(err).Msg("error validating the token")
		return nil, fmt.Errorf("invalid token: %s", err)
	}

	return token, nil
}
