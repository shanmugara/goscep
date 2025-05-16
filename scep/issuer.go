package scep

import (
	rand2 "crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"math/big"
	"math/rand"
	"os"
	"strings"
	"time"
)

type stringSlice []string

var (
	CARoot            = "ca.crt"
	CARootKey         = "ca.key"
	ValidityYears     = 1
	AuthorizedDomains = stringSlice{"omegahome.net", "omegaworld.net"}
	ExtendedKeyUsage  []x509.ExtKeyUsage
	BC                *BasicConstraints
	KeyUsages         []x509.KeyUsage
)

func (c *CSR) CSRValidate() error {
	fmt.Printf("CSR Validate %s", c.CsrPEM)

	logger := c.Logger.WithFields(logrus.Fields{"csr": c.CsrPEM})
	logger.Info("Validating CSR: ", c.CsrPEM)
	csr, err := c.ParseCSR()
	if err != nil {
		return err
	}
	if err := csr.CheckSignature(); err != nil {
		logger.WithError(err).Error("Error checking CSR signature")
	} else {
		logger.Info("CSR signature valid")
	}
	// check if the CSR contains any domains we are not authorized to issue

	for _, san := range csr.DNSNames {
		if err := c.ValidateSuffix(san); err != nil {
			logger.WithError(err).Error("failed to validate san")
			return err
		}
	}

	if err := c.ValidateSuffix(csr.Subject.CommonName); err != nil {
		logger.WithError(err).Error("failed to validate common name")
		return err
	}

	logger.Info("sans: ", csr.DNSNames)
	logger.Info("commonName: ", csr.Subject.CommonName)

	if err = c.GetExtendedKeyUsage(); err != nil {
		logger.WithError(err).Error("Error validating CSR, GetExtendedKeyUsage")
	}

	return nil
}

func (c *CSR) ValidateSuffix(suffix string) error {
	logger := c.Logger.WithFields(logrus.Fields{"csr": c.CsrPEM})
	logger.Info("Validating suffix: ", suffix)

	for _, domain := range AuthorizedDomains {
		if strings.HasSuffix(suffix, domain) {
			return nil
		}
	}
	return errors.New("unauthorized for domain: " + suffix)
}

func (c *CSR) Issue() ([]byte, error) {
	logger := c.Logger.WithFields(logrus.Fields{"csr": c.CsrPEM})
	logger.Info("Issuing certificate: ", c.CsrPEM)
	csr, err := c.ParseCSR()
	if err != nil {
		return nil, err
	}
	var combinedKeyUsages x509.KeyUsage
	for _, ku := range KeyUsages {
		combinedKeyUsages |= ku
	}

	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(rand.Int63()),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(ValidityYears, 0, 0),
		KeyUsage:     combinedKeyUsages,
		ExtKeyUsage:  ExtendedKeyUsage,
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		IsCA:         BC.IsCA,
		MaxPathLen:   BC.MaxPathLen,
	}

	caPEM, err := os.ReadFile(CARoot)
	if err != nil {
		logger.WithError(err).Error("Error reading CA certificate")
		return nil, err
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" {
		logger.WithError(err).Error("Error reading CA certificate, invalid CA certificate")
		return nil, errors.New("error reading CA certificate, invalid CA certificate")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		logger.WithError(err).Error("Error parsing CA certificate")
		return nil, err
	}
	caKeyPEM, err := os.ReadFile("ca.key")
	if err != nil {
		logger.WithError(err).Error("Error reading CA key")
		return nil, err
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil || caKeyBlock.Type != "PRIVATE KEY" {
		logger.WithError(err).Error("Error reading CA key, invalid CA key")
		return nil, errors.New("error reading CA key, invalid CA key")
	}
	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		logger.WithError(err).Error("Error parsing CA key")
		return nil, err
	}
	certDER, err := x509.CreateCertificate(rand2.Reader, &certTemplate, caCert, csr.PublicKey, caKey)
	if err != nil {
		logger.WithError(err).Error("Error creating certificate")
		return nil, err
	}
	certPEM := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	pemBytes := pem.EncodeToMemory(certPEM)

	return pemBytes, nil
}

func (c *CSR) ParseCSR() (*x509.CertificateRequest, error) {
	logger := c.Logger.WithFields(logrus.Fields{"csr": c.CsrPEM})
	logger.Info("Parsing CSR")
	csrPEM, err := os.ReadFile(c.CsrPEM)
	if err != nil {
		logger.WithError(err).Error("Error reading CSR")
		return nil, err
	}
	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		logger.WithError(err).Error("Error reading CSR, invalid CSR")
		return nil, errors.New("error reading CSR, invalid CSR")
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		logger.WithError(err).Error("Error parsing CSR")
		return nil, err
	}
	return csr, nil
}

func (c *CSR) GetExtendedKeyUsage() error {
	logger := c.Logger.WithFields(logrus.Fields{"csr": c.CsrPEM})
	logger.Info("Getting extended key usage")
	csr, err := c.ParseCSR()
	if err != nil {
		return err
	}

	for _, ext := range csr.Extensions {
		fmt.Println("ext: ", ext.Id)
		fmt.Println("value: ", ext.Value)
		switch {
		case ext.Id.Equal([]int{2, 5, 29, 19}):
			//basicConstraints
			var bc BasicConstraints
			_, err := asn1.Unmarshal(ext.Value, &bc)

			BC = &bc

			if err != nil {
				logger.WithError(err).Error("Error parsing Basic Constraints")
			}
			logger.Infof("Using Basic Constraints maxPathLen: %v", BC.MaxPathLen)
			logger.Infof("Using Basic Constraints isCA: %v", BC.IsCA)

		case ext.Id.Equal([]int{2, 5, 29, 15}):
			//usageBits
			var usageBits asn1.BitString

			_, err := asn1.Unmarshal(ext.Value, &usageBits)
			if err != nil {
				logger.WithError(err).Error("Error parsing usagebits")
			} else {
				logger.Info("Usage bits: ", usageBits)
				for i := 0; i < usageBits.BitLength; i++ {
					if usageBits.At(i) == 1 {
						logger.Info("Key usage: ", keyUsageNames[i])
						switch i {
						case 0:
							KeyUsages = append(KeyUsages, x509.KeyUsageDigitalSignature)
						case 1:
							KeyUsages = append(KeyUsages, x509.KeyUsageContentCommitment)
						case 2:
							KeyUsages = append(KeyUsages, x509.KeyUsageKeyEncipherment)
						case 3:
							KeyUsages = append(KeyUsages, x509.KeyUsageDataEncipherment)
						case 4:
							KeyUsages = append(KeyUsages, x509.KeyUsageKeyAgreement)
						case 5:
							KeyUsages = append(KeyUsages, x509.KeyUsageCertSign)
						case 6:
							KeyUsages = append(KeyUsages, x509.KeyUsageCRLSign)
						case 7:
							KeyUsages = append(KeyUsages, x509.KeyUsageEncipherOnly)
						case 8:
							KeyUsages = append(KeyUsages, x509.KeyUsageDecipherOnly)
						}
					} else {
						logger.Info("Key usage not set: ", keyUsageNames[i])

					}
				}
			}

		case ext.Id.Equal([]int{2, 5, 29, 37}):
			//extendedKeyUsage
			var extKeyUsage []asn1.ObjectIdentifier
			_, err := asn1.Unmarshal(ext.Value, &extKeyUsage)
			if err != nil {
				logger.WithError(err).Error("Error parsing extended key usage")
			} else {
				for _, id := range extKeyUsage {
					switch {
					case id.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 1}):
						logger.Info("serverAuth")
						ExtendedKeyUsage = append(ExtendedKeyUsage, x509.ExtKeyUsageServerAuth)
					case id.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 2}):
						logger.Info("clientAuth")
						ExtendedKeyUsage = append(ExtendedKeyUsage, x509.ExtKeyUsageClientAuth)
					case id.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 3}):
						logger.Info("codeSigning")
						ExtendedKeyUsage = append(ExtendedKeyUsage, x509.ExtKeyUsageCodeSigning)
					case id.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 4}):
						logger.Info("emailProtection")
						ExtendedKeyUsage = append(ExtendedKeyUsage, x509.ExtKeyUsageEmailProtection)
					case id.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 5}):
						logger.Info("ipsecEndSystem")
						ExtendedKeyUsage = append(ExtendedKeyUsage, x509.ExtKeyUsageIPSECEndSystem)
					case id.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 6}):
						logger.Info("ipsecTunnel")
						ExtendedKeyUsage = append(ExtendedKeyUsage, x509.ExtKeyUsageIPSECTunnel)
					case id.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 7}):
						logger.Info("ipsecUser")
						ExtendedKeyUsage = append(ExtendedKeyUsage, x509.ExtKeyUsageIPSECUser)
					case id.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 8}):
						logger.Info("timeStamping")
						ExtendedKeyUsage = append(ExtendedKeyUsage, x509.ExtKeyUsageTimeStamping)
					default:
						logger.Info("Unknown extended key usage: ", id)
					}
				}
			}

		}
	}
	return nil
}
