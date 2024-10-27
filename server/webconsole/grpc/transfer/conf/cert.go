package conf

import (
	_ "embed"
)

//go:embed server.key
var ServerKey []byte

//go:embed server.crt
var ServerCert []byte

//go:embed ca.crt
var CaCert []byte
