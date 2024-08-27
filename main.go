package main

import (
	"demo/authen"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func middlerware(envFile map[string]string) gin.HandlerFunc {
	return func(c *gin.Context) {
		err := authen.Validate(c, envFile)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		c.Next()
	}
}

func main() {
	r := gin.Default()
	envFile, _ := godotenv.Read(".env")
	login := r.Group("/authen")
	login.Use(middlerware(envFile))
	{
		login.GET("/login", func(c *gin.Context) {
			claim, _ := authen.GetClaim(c)
			c.String(http.StatusOK, claim.Username)
		})
	}
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	r.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}
