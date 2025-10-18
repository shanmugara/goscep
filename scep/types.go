package scep

import (
	"crypto/x509"
	"strings"

	"github.com/sirupsen/logrus"
)

type CSR struct {
	CsrPEM           string         `json:"csrpem"`
	CsrB64           string         `json:"csrb64"`
	AuthToken        string         `json:"authtoken" required:"true"`
	Logger           *logrus.Logger `json:"-"`
	BC               BasicConstraints
	KeyUsages        []x509.KeyUsage
	ExtendedKeyUsage []x509.ExtKeyUsage
}

type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSlice) Set(value string) error {
	parts := strings.Split(value, ",")
	for _, part := range parts {
		*s = append(*s, strings.TrimSpace(part))
	}
	return nil
}

type BasicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional"`
}

var keyUsageNames = map[int]string{
	0: "DigitalSignature",
	1: "ContentCommitment", // a.k.a. NonRepudiation
	2: "KeyEncipherment",
	3: "DataEncipherment",
	4: "KeyAgreement",
	5: "KeyCertSign",
	6: "CRLSign",
	7: "EncipherOnly",
	8: "DecipherOnly",
}
