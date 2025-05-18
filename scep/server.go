package scep

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"net/http"
)

var (
	Server = "localhost"
	Port   = 8080
)

func Start() {
	logger := logrus.New()
	logger.Infof("Starting server %s on port %d", Server, Port)
	router := gin.Default()
	router.POST("/v1/cert/request", Request())

	err := router.Run(fmt.Sprintf(":%d", Port))
	if err != nil {
		logger.Fatal("failed to start server", err)
		return
	}
}

func Request() gin.HandlerFunc {
	return func(c *gin.Context) {
		var csr CSR
		if err := c.ShouldBindJSON(&csr); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		csr.Logger = logrus.New()
		if err := csr.CSRValidate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		if pemBytes, err := csr.Issue(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusOK, gin.H{"certificate": string(pemBytes)})
		}
	}
}
