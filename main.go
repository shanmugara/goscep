package main

import (
	"bbgithub.dev.bloomberg.com/speriyas/goscep/scep"
	"flag"
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
)

func main() {
	var csrFile = flag.String("csrFile", "", "CSR file path")
	flag.StringVar(&scep.CARoot, "ca-root", "ca.crt", "CA Root file path")
	flag.StringVar(&scep.CARootKey, "ca-key", "ca.key", "CA Root Key file path")
	flag.IntVar(&scep.ValidityYears, "validity-years", 1, "Validity years")
	flag.Parse()
	fmt.Printf("CSR Validate %s", *csrFile)
	csr := scep.CSR{
		CsrPEM: *csrFile,
		Logger: logrus.New(),
	}
	fmt.Printf("csrPEM: %s", csr.CsrPEM)

	if err := csr.CSRValidate(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	} else {
		fmt.Println("CSR validation successful")
	}

	if pemBytes, err := csr.Issue(); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Certificate issued successfully")
		fmt.Printf("Certificate PEM: \n%s", string(pemBytes))
	}
}
