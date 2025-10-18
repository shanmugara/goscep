package main

import (
	"flag"
	"log"

	"github.com/shanmugara/goscep/scep"
	"github.com/sirupsen/logrus"
)

func main() {
	logger := logrus.New()
	scep.Config = &scep.ServerConfig{}
	// Define server config
	flag.StringVar(&scep.Config.CARoot, "ca-root", "ca.crt", "CA Root file path")
	flag.StringVar(&scep.Config.CARootKey, "ca-key", "ca.key", "CA Root Key file path")
	flag.IntVar(&scep.Config.ValidityYears, "validity-years", 1, "Validity years")
	flag.IntVar(&scep.Config.Port, "port", 8080, "Port to run the server on")
	flag.StringVar(&scep.Config.Server, "server", "0.0.0.0", "Server address")
	flag.Var(&scep.Config.AuthorizedDomains, "authorized-domains", "Comma separated list of authorized domains")

	flag.Parse()

	logger.Infof("Authorized Domains: %v", scep.Config.AuthorizedDomains)

	err := scep.Start()
	if err != nil {
		log.Fatal("failed to start gin server", err)
	}
}
