package scep

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

func (c *CSR) CSRValidate() error {
	logger := c.Logger.WithFields(logrus.Fields{"csr": c.CsrPEM})
	logger.Debug("Validating CSR: ", c.CsrPEM)
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

	if err = c.GetExtendedKeyUsage(csr); err != nil {
		logger.WithError(err).Error("Error validating CSR, GetExtendedKeyUsage")
		return err
	}
	// store the parsed CSR in the struct for future use
	c.Csr = csr

	return nil
}

func (c *CSR) ValidateSuffix(suffix string) error {
	logger := c.Logger.WithFields(logrus.Fields{"csr": c.CsrPEM})
	logger.Debug("Validating suffix: ", suffix)

	for _, domain := range Config.AuthorizedDomains {
		if strings.HasSuffix(suffix, domain) {
			return nil
		}
	}
	return errors.New("unauthorized for domain: " + suffix)
}

func (c *CSR) Issue() ([]byte, error) {
	logger := c.Logger.WithFields(logrus.Fields{"csr": c.CsrPEM})
	logger.Info("Issuing certificate: ", c.CsrPEM)

	var combinedKeyUsages x509.KeyUsage
	for _, ku := range c.KeyUsages {
		combinedKeyUsages |= ku
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		logger.WithError(err).Error("Error generating certificate serial number")
		return nil, err
	}

	certTemplate := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               c.Csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(Config.ValidityYears, 0, 0),
		KeyUsage:              combinedKeyUsages,
		ExtKeyUsage:           c.ExtendedKeyUsage,
		DNSNames:              c.Csr.DNSNames,
		IPAddresses:           c.Csr.IPAddresses,
		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	caPEM, err := os.ReadFile(Config.CARoot)
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
	caKeyPEM, err := os.ReadFile(Config.CARootKey)
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
	certDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, caCert, c.Csr.PublicKey, caKey)
	if err != nil {
		logger.WithError(err).Error("Error creating certificate")
		return nil, err
	}
	certPEM := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	pemBytes := pem.EncodeToMemory(certPEM)

	return pemBytes, nil
}

func (c *CSR) ParseCSR() (*x509.CertificateRequest, error) {
	var csrPEM []byte
	var err error
	logger := c.Logger.WithFields(logrus.Fields{"csr": c.CsrPEM})
	logger.Info("Parsing CSR")

	if c.CsrPEM != "" {
		return nil, fmt.Errorf("CSR PEM is deprecated, use CSR B64 or CSR Raw instead")
	} else if c.CsrB64 != "" {
		csrPEM, err = base64.StdEncoding.DecodeString(c.CsrB64)
		if err != nil {
			logger.WithError(err).Error("Error decoding CSR")
			return nil, err
		}
	} else if len(c.CsrRaw) > 0 {
		csrPEM = c.CsrRaw
	} else {
		logger.Error("No CSR provided")
		return nil, errors.New("no CSR provided")
	}

	return ParseCSRbytes(csrPEM)
}

func ParseCSRbytes(csrBytes []byte) (*x509.CertificateRequest, error) {
	csrBlock, _ := pem.Decode(csrBytes)
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("error reading CSR, invalid CSR")
	}

	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, err
	}

	if len(csr.DNSNames) == 0 {
		csr.DNSNames = append(csr.DNSNames, csr.Subject.CommonName)
	}
	return csr, nil
}

func (c *CSR) GetExtendedKeyUsage(csr *x509.CertificateRequest) error {
	logger := c.Logger.WithFields(logrus.Fields{"csr": c.CsrPEM})
	logger.Info("Getting extended key usage")

	for _, ext := range csr.Extensions {
		switch {
		case ext.Id.Equal([]int{2, 5, 29, 19}):
			//basicConstraints
			var bc BasicConstraints
			_, err := asn1.Unmarshal(ext.Value, &bc)

			c.BC = bc

			if err != nil {
				logger.WithError(err).Error("Error parsing Basic Constraints")
			}
			logger.Debugf("Using Basic Constraints maxPathLen: %v", c.BC.MaxPathLen)
			logger.Debugf("Using Basic Constraints isCA: %v", c.BC.IsCA)

		case ext.Id.Equal([]int{2, 5, 29, 15}):
			//usageBits
			var usageBits asn1.BitString

			_, err := asn1.Unmarshal(ext.Value, &usageBits)
			if err != nil {
				logger.WithError(err).Error("Error parsing usagebits")
			} else {
				logger.Debug("Usage bits: ", usageBits)
				for i := 0; i < usageBits.BitLength; i++ {
					if usageBits.At(i) == 1 {
						logger.Info("Key usage: ", keyUsageNames[i])
						switch i {
						case 0:
							c.KeyUsages = append(c.KeyUsages, x509.KeyUsageDigitalSignature)
						case 1:
							c.KeyUsages = append(c.KeyUsages, x509.KeyUsageContentCommitment)
						case 2:
							c.KeyUsages = append(c.KeyUsages, x509.KeyUsageKeyEncipherment)
						case 3:
							c.KeyUsages = append(c.KeyUsages, x509.KeyUsageDataEncipherment)
						case 4:
							c.KeyUsages = append(c.KeyUsages, x509.KeyUsageKeyAgreement)
						case 5:
							c.KeyUsages = append(c.KeyUsages, x509.KeyUsageCertSign)
						case 6:
							c.KeyUsages = append(c.KeyUsages, x509.KeyUsageCRLSign)
						case 7:
							c.KeyUsages = append(c.KeyUsages, x509.KeyUsageEncipherOnly)
						case 8:
							c.KeyUsages = append(c.KeyUsages, x509.KeyUsageDecipherOnly)
						default:
							logger.Errorf("Unknown key usage: %s", keyUsageNames[i])
						}
					} else {
						logger.Errorf("Key usage not set: %s", keyUsageNames[i])

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
						logger.Info("ExtendedKeyUsage: serverAuth")
						c.ExtendedKeyUsage = append(c.ExtendedKeyUsage, x509.ExtKeyUsageServerAuth)
					case id.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 2}):
						logger.Info("ExtendedKeyUsage: clientAuth")
						c.ExtendedKeyUsage = append(c.ExtendedKeyUsage, x509.ExtKeyUsageClientAuth)
					case id.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 3}):
						logger.Info("ExtendedKeyUsage: codeSigning")
						c.ExtendedKeyUsage = append(c.ExtendedKeyUsage, x509.ExtKeyUsageCodeSigning)
					case id.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 4}):
						logger.Info("ExtendedKeyUsage: emailProtection")
						c.ExtendedKeyUsage = append(c.ExtendedKeyUsage, x509.ExtKeyUsageEmailProtection)
					case id.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 5}):
						logger.Info("ExtendedKeyUsage: ipsecEndSystem")
						c.ExtendedKeyUsage = append(c.ExtendedKeyUsage, x509.ExtKeyUsageIPSECEndSystem)
					case id.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 6}):
						logger.Info("ExtendedKeyUsage: ipsecTunnel")
						c.ExtendedKeyUsage = append(c.ExtendedKeyUsage, x509.ExtKeyUsageIPSECTunnel)
					case id.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 7}):
						logger.Info("ExtendedKeyUsage: ipsecUser")
						c.ExtendedKeyUsage = append(c.ExtendedKeyUsage, x509.ExtKeyUsageIPSECUser)
					case id.Equal([]int{1, 3, 6, 1, 5, 5, 7, 3, 8}):
						logger.Info("ExtendedKeyUsage: timeStamping")
						c.ExtendedKeyUsage = append(c.ExtendedKeyUsage, x509.ExtKeyUsageTimeStamping)
					default:
						logger.Errorf("Unknown extended key usage: %d", id)
					}
				}
			}

		}
	}
	return nil
}
