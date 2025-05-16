package scep

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"net/http"
)

func Start(server string, port int) {
	logger := logrus.New()
	logger.Infof("Starting server on port %d", port)
	router := gin.Default()
	router.POST("/v1/cert/request", Process())

	err := router.Run(fmt.Sprintf(":%d", port))
	if err != nil {
		logger.Fatal("failed to start server", err)
		return
	}
}

func Process() gin.HandlerFunc {
	return func(c *gin.Context) {
		var csr *CSR
		if err := c.ShouldBindJSON(&csr); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		if err := csr.CSRValidate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}

	}
}
