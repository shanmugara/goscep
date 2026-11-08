package scep

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/gin-gonic/gin"
	"github.com/shanmugara/spireauthlib"
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
	ctx := context.Background()
	tlsCtx, tsCancel := context.WithTimeout(ctx, 15*time.Second)
	defer tsCancel()

	mtlsRouter := gin.Default()
	mtlsRouter.POST("/v1/cert/request", Request())
	// get spire tls config
	sAuth := spireauthlib.ServerAuth{Logger: Logger}
	mtlsConfig, err := sAuth.GetTlsConfig(tlsCtx)

	if err != nil {
		Logger.Fatalf("failed to get TLS config: %v", err)
		return err
	}
	srvMtls := &http.Server{
		Addr:      fmt.Sprintf("%s:%d", Config.Server, Config.PortMtls),
		Handler:   mtlsRouter,
		TLSConfig: mtlsConfig,
	}

	tlsRouter := gin.Default()
	tlsRouter.POST("/v1/cert/request", Request())

	tlsConfig, err := BuildTlsConfig()
	if err != nil {
		Logger.Fatalf("failed to build TLS config: %v", err)
		return err
	}

	srvTls := &http.Server{
		Addr:      fmt.Sprintf("%s:%d", Config.Server, Config.PortTls),
		Handler:   tlsRouter,
		TLSConfig: tlsConfig,
	}
	//Blocking call to start the server
	go func() {
		Logger.Infof("Starting mtls server %s on port %d", Config.Server, Config.PortMtls)
		if err := srvMtls.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			Logger.Fatalf("mtls listen: %s\n", err)
		}
	}()
	//Blocking call to start the server
	go func() {
		Logger.Infof("Starting tls server %s on port %d", Config.Server, Config.PortTls)
		if err := srvTls.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			Logger.Fatalf("tls listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 5 seconds.
	quit := make(chan struct{})
	<-quit
	Logger.Println("Shutting down server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 15*time.Second)
	defer shutdownCancel()
	if err := srvMtls.Shutdown(shutdownCtx); err != nil {
		Logger.Fatal("Server forced to shutdown:", err)
	}
	if err := srvTls.Shutdown(shutdownCtx); err != nil {
		Logger.Fatal("Server forced to shutdown:", err)
	}

	Logger.Println("Server exiting")
	return nil
}

func BuildTlsConfig() (*tls.Config, error) {
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair(Config.TlsCert, Config.TlsKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate and key: %v", err)
	}

	rootCAs := x509.NewCertPool()
	caCert, err := os.ReadFile(Config.CARoot)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA root certificate: %v", err)
	}
	if ok := rootCAs.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("failed to append CA root certificate to pool")
	}
	allowedCNs, err := LoadAllowedCNs()
	if err != nil {
		Logger.Warnf("failed to load allowed CNs: %v", err)
		allowedCNs = []string{}
	}

	// set client authentication to require and verify client certificate

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    rootCAs,
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no client certificate presented")
			}
			cn := cs.PeerCertificates[0].Subject.CommonName
			for _, allowed := range allowedCNs {
				if cn == allowed {
					return nil
				}
			}
			Logger.Warnf("rejected client CN: %s", cn)
			return fmt.Errorf("client CN %q not allowed", cn)
		},
	}

	return tlsConfig, nil
}

// AllowedCNsConfig reads from the YAML file containing allowed client CNs
// and returns them as a slice of strings
func LoadAllowedCNs() ([]string, error) {
	var cfg AllowedCNsConfig
	data, err := os.ReadFile(Config.AllowedCNs)
	if err != nil {
		return nil, fmt.Errorf("failed to read allowed CNs from %s: %w", Config.AllowedCNs, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return cfg.AllowedCNs, nil
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
		if csr.BC.IsCA {
			c.JSON(http.StatusBadRequest, gin.H{"error": "refusing to issue type CA"})
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
