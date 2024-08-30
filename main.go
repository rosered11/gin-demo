package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"dev.azure.com/tms-public/library/_git/tmscore.git/middleware"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/jwk"
)

// func myMiddleware(envFile map[string]string) gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		err := authen.Validate(c, envFile)
// 		if err != nil {
// 			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
// 			return
// 		}
// 		c.Next()
// 	}
// }

func main() {
	r := gin.New()

	// Fetch the JWK from the URI
	keySet, err := jwk.Fetch(context.Background(),
		fmt.Sprintf("%s/%s/%s/discovery/v2.0/keys",
			os.Getenv("AZURE_INSTANCE"),
			os.Getenv("AZURE_DOMAIN"),
			os.Getenv("AZURE_TENANT")))
	if err != nil {
		log.Fatalf("failed to fetch JWK: %s", err)
	}

	r.Use(middleware.DefaultStructuredLogger())
	r.Use(gin.Recovery())
	r.SetTrustedProxies(nil)
	login := r.Group("/authen")
	login.Use(middleware.Authenticator(keySet))
	{
		login.GET("/login", func(c *gin.Context) {
			claim, _ := middleware.GetClaim(c)
			c.String(http.StatusInternalServerError, claim.Username)
		})
	}
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	r.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}
