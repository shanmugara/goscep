package scep

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

var Config *ServerConfig
var Logger *logrus.Logger

func Start() error {
	// Ensure a logger is available for the package
	if Logger == nil {
		Logger = logrus.New()
	}
	if Config == nil {
		return fmt.Errorf("server config is nil")
	}
	Logger.Infof("Starting server %s on port %d", Config.Server, Config.Port)
	ctx := context.Background()
	tlsCtx, tsCancel := context.WithTimeout(ctx, 15*time.Second)
	defer tsCancel()

	router := gin.Default()
	router.POST("/v1/cert/request", Request())
	// get spire tls config
	tlsConfig, err := GetTlsConfig(tlsCtx)
	if err != nil {
		Logger.Fatalf("failed to get TLS config: %v", err)
		return err
	}
	srv := &http.Server{
		Addr:      fmt.Sprintf("%s:%d", Config.Server, Config.Port),
		Handler:   router,
		TLSConfig: tlsConfig,
	}

	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			Logger.Fatalf("listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 5 seconds.
	quit := make(chan struct{})
	<-quit
	Logger.Println("Shutting down server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 15*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		Logger.Fatal("Server forced to shutdown:", err)
	}

	Logger.Println("Server exiting")
	return nil
}

func Request() gin.HandlerFunc {
	return func(c *gin.Context) {
		var csr CSR
		if err := c.ShouldBindJSON(&csr); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// use package logger if present, otherwise fall back to a new one
		if Logger == nil {
			csr.Logger = logrus.New()
		} else {
			csr.Logger = Logger
		}
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
