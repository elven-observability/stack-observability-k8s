// Copyright Elven Observability. Licensed under the Apache License, Version 2.0.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	config, err := parseConfig([]byte(os.Getenv("ELVEN_INJECTION_CONFIG")))
	if err != nil {
		log.Fatal(err)
	}
	certFile, keyFile := os.Getenv("ELVEN_WEBHOOK_CERT"), os.Getenv("ELVEN_WEBHOOK_KEY")
	if certFile == "" {
		certFile = "/etc/elven/webhook/tls.crt"
	}
	if keyFile == "" {
		keyFile = "/etc/elven/webhook/tls.key"
	}
	tlsConfig, err := webhookTLSConfig(certFile, keyFile, os.Getenv("ELVEN_WEBHOOK_CLIENT_CA"))
	if err != nil {
		log.Fatal(err)
	}
	op := newOperator(config)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mutate", op.serveMutate)
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", "text/plain")
		writer.Header().Set("Cache-Control", "no-store")
		_, _ = writer.Write([]byte("Elven instrumentation operator ready\n"))
	})
	address := os.Getenv("ELVEN_WEBHOOK_ADDR")
	if address == "" {
		address = ":9443"
	}
	server := &http.Server{Addr: address, Handler: mux, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Print("Elven instrumentation operator started; request objects and credentials are never logged")
	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("Elven webhook server stopped unexpectedly")
	}
}

func webhookTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return nil, errors.New("Elven webhook serving certificate/key are unavailable or invalid")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// Read projected Secret paths again on handshakes so certificate rotation
		// does not require a process restart. Never log key bytes or request data.
		certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
		return &certificate, err
	}}
	if clientCAFile != "" {
		pem, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, errors.New("Elven webhook client CA is unavailable")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("Elven webhook client CA is invalid")
		}
		config.ClientCAs, config.ClientAuth = pool, tls.RequireAndVerifyClientCert
	}
	return config, nil
}
