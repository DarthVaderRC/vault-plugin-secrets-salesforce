package main

import (
	"log"
	"os"

	salesforce "github.com/DarthVaderRC/vault-plugin-secrets-salesforce"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Fatal(err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: salesforce.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatalf("plugin shutting down: %v", err)
	}
}
