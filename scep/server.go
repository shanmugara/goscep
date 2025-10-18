package scep

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

var Config *ServerConfig

func Start() error {
	logger := logrus.New()
	logger.Infof("Starting server %s on port %d", Config.Server, Config.Port)
	router := gin.Default()
	router.POST("/v1/cert/request", Request())

	err := router.Run(fmt.Sprintf("%s:%d", Config.Server, Config.Port))
	if err != nil {
		return err
	}
	return nil
}

func Request() gin.HandlerFunc {
	return func(c *gin.Context) {
		var csr CSR
		if err := c.ShouldBindJSON(&csr); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		csr.Logger = logrus.New()
		if err := csr.CSRValidate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if pemBytes, err := csr.Issue(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		} else {
			c.JSON(http.StatusOK, gin.H{"certificate": string(pemBytes)})
		}
	}
}
