package scep

import (
	"crypto/x509"
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

type BasicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional"`
}

//type KeyUsage struct {
//	digitalSignature asn1.BitString `asn1:"optional"`
//	nonRepudiation   asn1.BitString `asn1:"optional"`
//	keyEncipherment  asn1.BitString `asn1:"optional"`
//	dataEncipherment asn1.BitString `asn1:"optional"`
//	keyAgreement     asn1.BitString `asn1:"optional"`
//	keyCertSign      asn1.BitString `asn1:"optional"`
//	cRLSign          asn1.BitString `asn1:"optional"`
//	encipherOnly     asn1.BitString `asn1:"optional"`
//	decipherOnly     asn1.BitString `asn1:"optional"`
//}

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
