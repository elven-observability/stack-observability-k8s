// Copyright Elven Observability. Licensed under the Apache License, Version 2.0.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type certificateFixture struct {
	certFile, keyFile, caFile string
	client                    tls.Certificate
	roots                     *x509.CertPool
}

func tlsFixture(t *testing.T) certificateFixture {
	t.Helper()
	folder := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Elven synthetic test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(6 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	makeLeaf := func(name string, usage x509.ExtKeyUsage, serial int64) ([]byte, []byte) {
		t.Helper()
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(5 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if usage == x509.ExtKeyUsageServerAuth {
			leaf.DNSNames = []string{"localhost", "elven-webhook.elven-observability.svc"}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalPKCS8PrivateKey(leafKey)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	}
	certPEM, keyPEM := makeLeaf("Elven synthetic server", x509.ExtKeyUsageServerAuth, 2)
	clientPEM, clientKeyPEM := makeLeaf("Elven synthetic client", x509.ExtKeyUsageClientAuth, 3)
	client, err := tls.X509KeyPair(clientPEM, clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	fixture := certificateFixture{certFile: filepath.Join(folder, "tls.crt"), keyFile: filepath.Join(folder, "tls.key"), caFile: filepath.Join(folder, "ca.crt"), client: client, roots: x509.NewCertPool()}
	fixture.roots.AppendCertsFromPEM(caPEM)
	for path, data := range map[string][]byte{fixture.certFile: certPEM, fixture.keyFile: keyPEM, fixture.caFile: caPEM} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func TestServingTLSAndOptionalClientAuthenticationUseRealHandshakes(t *testing.T) {
	fixture := tlsFixture(t)
	config, err := webhookTLSConfig(fixture.certFile, fixture.keyFile, fixture.caFile)
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS12 || config.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("serving TLS policy not enforced")
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(newOperator(configForTest(t)).serveMutate))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = config
	server.StartTLS()
	defer server.Close()
	raw, _ := json.Marshal(admissionReview{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview", Request: requestForTest(t, podForTest("java"))})
	client := func(certificates []tls.Certificate, roots *x509.CertPool, max uint16) *http.Client {
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: "localhost", RootCAs: roots, Certificates: certificates, MinVersion: tls.VersionTLS10, MaxVersion: max}}}
	}
	valid := client([]tls.Certificate{fixture.client}, fixture.roots, tls.VersionTLS13)
	response, err := valid.Post(server.URL, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("valid TLS admission failed")
	}
	withoutCertificate := client(nil, fixture.roots, tls.VersionTLS13)
	response, err = withoutCertificate.Post(server.URL, "application/json", bytes.NewReader(raw))
	if err == nil {
		response.Body.Close()
		t.Fatal("client certificate requirement bypassed")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("failure was not certificate-related: %v", err)
	}
	wrongCA := client([]tls.Certificate{fixture.client}, x509.NewCertPool(), tls.VersionTLS13)
	response, err = wrongCA.Post(server.URL, "application/json", bytes.NewReader(raw))
	if err == nil {
		response.Body.Close()
		t.Fatal("untrusted server CA accepted")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("failure was not CA-related: %v", err)
	}
	oldTLS := client([]tls.Certificate{fixture.client}, fixture.roots, tls.VersionTLS11)
	response, err = oldTLS.Post(server.URL, "application/json", bytes.NewReader(raw))
	if err == nil {
		response.Body.Close()
		t.Fatal("TLS older than 1.2 accepted")
	}
	if !strings.Contains(err.Error(), "protocol version") {
		t.Fatalf("failure was not protocol version-related: %v", err)
	}
}

func TestServingTLSConfigFailsClosedAndReloadsProjectedCertificates(t *testing.T) {
	fixture := tlsFixture(t)
	for _, args := range [][3]string{{"missing", fixture.keyFile, ""}, {fixture.certFile, "missing", ""}, {fixture.certFile, fixture.keyFile, "missing"}} {
		if _, err := webhookTLSConfig(args[0], args[1], args[2]); err == nil {
			t.Fatal("missing TLS material accepted")
		}
	}
	config, err := webhookTLSConfig(fixture.certFile, fixture.keyFile, "")
	if err != nil {
		t.Fatal(err)
	}
	if config.ClientAuth != tls.NoClientCert {
		t.Fatal("default Kubernetes webhook must not require an unconfigured API-server client cert")
	}
	if _, err := config.GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.keyFile, []byte("invalid-synthetic-key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.GetCertificate(nil); err == nil {
		t.Fatal("rotated invalid key ignored")
	}
}
