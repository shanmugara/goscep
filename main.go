package main

import (
	"bbgithub.dev.bloomberg.com/speriyas/goscep/scep"
	"flag"
)

func main() {
	//var csrFile = flag.String("csrFile", "", "CSR file path")
	//var csrB64 = flag.String("csrB64", "", "CSR Base64 file path")
	flag.StringVar(&scep.CARoot, "ca-root", "ca.crt", "CA Root file path")
	flag.StringVar(&scep.CARootKey, "ca-key", "ca.key", "CA Root Key file path")
	flag.IntVar(&scep.ValidityYears, "validity-years", 1, "Validity years")
	flag.IntVar(&scep.Port, "port", 8080, "Port to run the server on")
	flag.StringVar(&scep.Server, "server", "localhost", "Server address")

	flag.Parse()
	//fmt.Printf("CSR Validate %s", *csrFile)
	//csr := scep.CSR{
	//	CsrPEM: *csrFile,
	//	CsrB64: *csrB64,
	//	Logger: logrus.New(),
	//}
	//fmt.Printf("csrPEM: %s", csr.CsrPEM)
	//fmt.Printf("csrB64: %s", csr.CsrB64)
	scep.Start()
	//
	//	if err := csr.CSRValidate(); err != nil {
	//		os.Exit(1)
	//	}
	//
	//	if pemBytes, err := csr.Issue(); err != nil {
	//		fmt.Println(err)
	//	} else {
	//		fmt.Println("Certificate issued successfully")
	//		fmt.Printf("Certificate PEM: \n%s", string(pemBytes))
	//	}
}
