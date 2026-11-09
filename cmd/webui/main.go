package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/shanmugara/goscep/webui"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	listen := flag.String("listen", ":443", "Address for the web UI HTTPS listener")
	usersFile := flag.String("users", "/scep/users.yaml", "Users file with bcrypt password hashes and allowed domains")
	tlsCert := flag.String("tls-cert", "/scep/webui-tls.crt", "Web UI HTTPS certificate file path")
	tlsKey := flag.String("tls-key", "/scep/webui-tls.key", "Web UI HTTPS key file path")
	clientCert := flag.String("client-cert", "/scep/webui-client.crt", "Client certificate presented to goscep on 8443 (CN must be in goscep's allowedcns.yaml)")
	clientKey := flag.String("client-key", "/scep/webui-client.key", "Client key presented to goscep on 8443")
	caFile := flag.String("ca", "/scep/ca.crt", "CA certificate used to verify goscep's 8443 server certificate")
	goscepURL := flag.String("goscep-url", "https://goscep:8443/v1/cert/request", "goscep TLS (8443) request endpoint")
	sessionTTL := flag.Duration("session-ttl", 30*time.Minute, "Idle timeout for web UI sessions")
	sessionKeyFile := flag.String("session-key-file", "", "File with at least 32 bytes used to sign session cookies (random per start if empty)")
	hashPassword := flag.Bool("hash-password", false, "Read a password from stdin, print its bcrypt hash for users.yaml and exit")
	flag.Parse()

	if *hashPassword {
		if err := printPasswordHash(); err != nil {
			log.Fatal(err)
		}
		return
	}

	logger := webui.Logger

	sessionKey, err := loadSessionKey(*sessionKeyFile)
	if err != nil {
		logger.Fatalf("failed to load session key: %v", err)
	}
	users, err := webui.NewUserStore(*usersFile)
	if err != nil {
		logger.Fatalf("failed to load users: %v", err)
	}
	client, err := webui.NewGoscepClient(*goscepURL, *clientCert, *clientKey, *caFile)
	if err != nil {
		logger.Fatalf("failed to set up goscep client: %v", err)
	}
	srv, err := webui.NewServer(users, client, sessionKey, *sessionTTL)
	if err != nil {
		logger.Fatalf("failed to set up web UI: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		logger.Infof("Starting web UI on %s, submitting CSRs to %s", *listen, *goscepURL)
		if err := httpSrv.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("web UI listen: %v", err)
		}
	}()

	<-ctx.Done()
	logger.Info("Shutting down web UI...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Errorf("web UI forced to shut down: %v", err)
	}
}

func loadSessionKey(path string) ([]byte, error) {
	if path == "" {
		webui.Logger.Warn("No -session-key-file set: using a random key, so sessions end on restart and are not shared between replicas")
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		return key, nil
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key = []byte(strings.TrimSpace(string(key)))
	if len(key) < 32 {
		return nil, fmt.Errorf("%s must contain at least 32 bytes", path)
	}
	return key, nil
}

func printPasswordHash() error {
	fmt.Fprint(os.Stderr, "Password: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return fmt.Errorf("failed to read password: %w", err)
	}
	password := strings.TrimRight(line, "\r\n")
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	fmt.Println(string(hash))
	return nil
}
