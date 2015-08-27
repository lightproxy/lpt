package certs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"time"
	"math/big"
	"encoding/pem"
	"errors"
)


var ErrInvalidCert = errors.New("Invalid Cert.")
var ErrInvalidKey = errors.New("Invalid RSA private key.")
var ErrIncorrectKey = errors.New("Incorrect RSA private key. (Public key not match)")

func encodeCert(der_data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block {
		Type: "CERTIFICATE",
		Bytes: der_data,
	})
}

func decodeCert(pem_data []byte) *x509.Certificate {
	// Looking for a block with type CERTIFICATE
	for block, rst := pem.Decode(pem_data); block != nil; block, rst = pem.Decode(rst) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// Maybe not we want actually.
			continue
		}
		return cert
	}
	return nil
}

func encodeRSAPrivateKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block {
		Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func decodeRSAPrivateKey(pem_data []byte) *rsa.PrivateKey {
	for block, rst := pem.Decode(pem_data); block != nil; block, rst = pem.Decode(rst) {
		if block.Type != "RSA PRIVATE KEY" {
			continue
		}
		pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Maybe not we want actually.
			continue
		}
		return pk
	}
	return nil
}

func correctRSAPrivateKey(cert *x509.Certificate, pk *rsa.PrivateKey) (res bool) {
	pubkey, res := cert.PublicKey.(*rsa.PublicKey)
	if !res {
		// Not even a RSA public key :(
		return
	}
	// E is very likely to be the same, so it should make things faster if we compare N first.
	return pk.PublicKey.N.Cmp(pubkey.N) == 0 && pk.PublicKey.E == pubkey.E
}

// TODO: allow to decode encrypted RSA private key with password.

// CreateCA actually creates a pair of private/public key, and a CA using/self-signed by that key.
// Private key is a newly created 4096-bit RSA key.
// Note: this is a really simplified function, and many not so important parts were hidden from user.
func CreateCA(
	// The valid length for this CA, recommended time is 10 years or longer, 
	// since this CA is not so critical even if it can be cracked 10 years later.
	// NOTE: In order to prevent inaccurate local time, NotValidBefore is set one day before time.Now
	valid_length time.Duration,
	// Organization, OrganizationUnit, Locality, Province are fixed to null.
	// So does StreetAddress, PostalCode, SerialNumber
	country, name string,
) (ca_pem []byte, key_pem []byte, err error) {
	// Refer to https://golang.org/pkg/crypto/x509/#CreateCertificate
	//
	// According to RFC3280, we SHOULD use SHA1 hash of public key bit string or unique values
	// as SubjectKeyID, but unfortunately, supporting all key type (RSA, ECDSA) is difficult.
	// So we use a sort of not-so-random way to implement: create SHA256 hash from a 256-bit
	// crypto-random string.

	// Step 1: Create a 4096 bit RSA key.

	pk, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}

	pk.Precompute()

	// Step 2: Generate random things.

	random_data := make([]byte, 32)
	left := 32
	for left > 0 {
		n, err := rand.Read(random_data[32 - left:])
		left -= n
		if err != nil {
			return nil, nil, err
		}
	}

	sub_id := sha256.Sum256(random_data)

	// Random 256-bit serial number.
	serial, err := rand.Int(rand.Reader, big.NewInt(0).Exp(big.NewInt(65536), big.NewInt(16), nil))

	if err != nil {
		return
	}

	// Step 3: Fill information to a *x509.Certificate

	cert := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Country: []string { country },
			CommonName: name,
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter: time.Now().Add(valid_length),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage { x509.ExtKeyUsageAny },
		BasicConstraintsValid: true,
		IsCA: true,
		SubjectKeyId: sub_id[:],
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// Step 4: Create it!

	cert_der, err := x509.CreateCertificate(rand.Reader, cert, cert, pk.Public(), pk)
	if err != nil {
		return
	}

	return encodeCert(cert_der), encodeRSAPrivateKey(pk), nil
}

// CreateClientCert creates a pair of private/public key, and a cert signed by CA created earlier.
// Private key is a newly created 4096-bit RSA key.
// Note: this is a really simplified function, and many not so important parts were hidden from user.
func CreateClientCert(
	// A pem which contained parent certificate used for sign the request, also its certification part will be append to cert.
	parent_pem []byte,
	// A pem which contained PCKS1 private key of parent certificate, used for sign.
	rsa_pem []byte,
	// The valid length for this client certification, recommended time is 1 year or so.
	// Signing a new certificate for a client is not so hard.
	// NOTE: In order to prevent inaccurate local time, NotValidBefore is set one day before time.Now
	valid_length time.Duration,
	// Organization, OrganizationUnit, Locality, Province are fixed to null.
	// So does StreetAddress, PostalCode, SerialNumber
	// Email is kind of important to identify client, so we added here.
	country, name, email string,
) (cert_pem []byte, key_pem []byte, err error) {

	// Step 1. convert CA and PK to internal form, and do a little check.
	parent := decodeCert(parent_pem)
	if parent == nil {
		err = ErrInvalidCert
		return
	}
	pkey := decodeRSAPrivateKey(rsa_pem)
	if pkey == nil {
		err = ErrInvalidKey
		return
	}
	if !correctRSAPrivateKey(parent, pkey) {
		err = ErrIncorrectKey
		return
	}

	// Step 2: Create a 4096 bit RSA key.

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}

	key.Precompute()

	// Step 3: Generate random things.

	random_data := make([]byte, 32)
	left := 32
	for left > 0 {
		n, err := rand.Read(random_data[32 - left:])
		left -= n
		if err != nil {
			return nil, nil, err
		}
	}

	sub_id := sha256.Sum256(random_data)

	// Random 256-bit serial number.
	serial, err := rand.Int(rand.Reader, big.NewInt(0).Exp(big.NewInt(65536), big.NewInt(16), nil))

	if err != nil {
		return
	}

	// Step 4: Fill information to a *x509.Certificate

	cert := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Country: []string { country },
			CommonName: name,
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter: time.Now().Add(valid_length),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage { x509.ExtKeyUsageAny },
		BasicConstraintsValid: true,
		IsCA: true,
		SubjectKeyId: sub_id[:],
		SignatureAlgorithm: x509.SHA256WithRSA,
		EmailAddresses: []string { email },
	}

	// Step 4: Create it!

	cert_der, err := x509.CreateCertificate(rand.Reader, cert, parent, key.Public(), pkey)
	if err != nil {
		return
	}

	return encodeCert(cert_der), encodeRSAPrivateKey(key), nil

}
