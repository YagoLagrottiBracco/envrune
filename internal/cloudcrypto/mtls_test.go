package cloudcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
)

// mtlsVectorPath holds test certificates the server's tests use to check
// that it presents a client certificate: an authority, a server certificate
// for localhost, and a client certificate. They are for tests only; write
// them again with ENVRUNE_WRITE_VECTORS=1.
var mtlsVectorPath = filepath.Join("..", "..", "cloud", "web", "src", "lib", "mtls-vector.json")

type mtlsVector struct {
	CA         string `json:"ca"`
	ServerCert string `json:"server_cert"`
	ServerKey  string `json:"server_key"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
}

func writeMTLSVector(t *testing.T) {
	t.Helper()
	issue := func(template, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (string, string, *x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, signerKey := parent, parentKey
		if parent == nil {
			signer, signerKey = template, key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(der)
		pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})), cert, key
	}
	base := func(serial int64, name string) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(30, 0, 0)}
	}
	ca := base(1, "EnvRune test authority")
	ca.IsCA, ca.BasicConstraintsValid, ca.KeyUsage = true, true, x509.KeyUsageCertSign
	caPEM, _, caCert, caKey := issue(ca, nil, nil)
	server := base(2, "localhost")
	server.DNSNames, server.IPAddresses = []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}
	server.KeyUsage, server.ExtKeyUsage = x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	serverPEM, serverKey, _, _ := issue(server, caCert, caKey)
	client := base(3, "envrune-test-client")
	client.KeyUsage, client.ExtKeyUsage = x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	clientPEM, clientKey, _, _ := issue(client, caCert, caKey)
	raw, _ := json.MarshalIndent(mtlsVector{CA: caPEM, ServerCert: serverPEM, ServerKey: serverKey, ClientCert: clientPEM, ClientKey: clientKey}, "", "  ")
	if err := os.WriteFile(mtlsVectorPath, append(raw, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestAClientCertificateIsSealedLikeAValue(t *testing.T) {
	if os.Getenv("ENVRUNE_WRITE_VECTORS") != "" {
		writeMTLSVector(t)
	}
	raw, err := os.ReadFile(mtlsVectorPath)
	if err != nil {
		t.Skipf("no vector file (%v); write it with ENVRUNE_WRITE_VECTORS=1", err)
	}
	var v mtlsVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	device, _ := NewDevice("alice", "laptop")
	proxy, _ := age.GenerateX25519Identity()
	r, err := device.SealSensitiveCertificate("org", "project", "env", "bank-certificate", 1, []byte(v.ClientCert), []byte(v.ClientKey), []string{"api.example.com"}, proxy.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	content, err := OpenSensitive(r, proxy)
	if err != nil || string(content.Certificate) != v.ClientCert || string(content.Key) != v.ClientKey || len(content.Value) != 0 {
		t.Fatalf("the proxy opened %+v: %v", content, err)
	}
	// A key that does not belong to the certificate is refused before it is sealed.
	if _, err := device.SealSensitiveCertificate("org", "project", "env", "bank-certificate", 1, []byte(v.ClientCert), []byte(v.ServerKey), []string{"api.example.com"}, proxy.Recipient().String()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a certificate with another key was sealed: %v", err)
	}
	if _, err := device.SealSensitiveCertificate("org", "project", "env", "bank-certificate", 1, []byte("not pem"), []byte("not pem"), []string{"api.example.com"}, proxy.Recipient().String()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("something that is not a certificate was sealed: %v", err)
	}
}
