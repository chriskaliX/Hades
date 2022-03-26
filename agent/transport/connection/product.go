package connection

import _ "embed"

//go:embed client.key
var ClientKey []byte

//go:embed client.crt
var ClientCert []byte

//go:embed ca.crt
var CaCert []byte

func init() {
	setDialOptions(CaCert, ClientKey, ClientCert, "hades.com")
}
