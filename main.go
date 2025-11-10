package main

import (
	"flag"
	"log"

	"github.com/shanmugara/goscep/scep"
	"github.com/sirupsen/logrus"
)

func main() {
	logger := logrus.New()
	scep.Logger = logger
	scep.Config = &scep.ServerConfig{}
	// Define server config
	flag.StringVar(&scep.Config.CARoot, "ca-root", "ca.crt", "Signing CA Root file path")
	flag.StringVar(&scep.Config.CARootKey, "ca-key", "ca.key", "Signing CA Root Key file path")
	flag.StringVar(&scep.Config.TlsCert, "tls-cert", "tls.crt", "TLS Certificate file path")
	flag.StringVar(&scep.Config.TlsKey, "tls-key", "tls.key", "TLS Key file path")
	flag.IntVar(&scep.Config.ValidityYears, "validity-years", 1, "Issued cert validity years")
	flag.IntVar(&scep.Config.PortMtls, "port", 8080, "PortMtls to run the server on")
	flag.IntVar(&scep.Config.PortTls, "port-tls", 8443, "PortTls to run the server on")
	flag.StringVar(&scep.Config.Server, "server", "0.0.0.0", "Listen server address")
	flag.Var(&scep.Config.AuthorizedDomains, "authorized-domains", "Comma separated list of authorized domains to issue")
	flag.StringVar(&scep.Config.SpiffeIDs, "spiffe-ids", "spiffeids.yaml", "Config file with list of Spiffe IDs allowed to access the SCEP server")

	flag.Parse()

	logger.Infof("Authorized Domains: %v", scep.Config.AuthorizedDomains)

	err := scep.Start()
	if err != nil {
		log.Fatal("failed to start gin server", err)
	}
}
