package connection

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"

	"go.uber.org/zap"
)

//go:embed client.key
var ClientKey []byte

//go:embed client.crt
var ClientCert []byte

//go:embed ca.crt
var CaCert []byte

// Notice: Do a modify here to specific the addresss
// As default, we use dns based LB
// func init() {
// }

// TLS configuration generator
func LoadTLSConfig(host string) *tls.Config {
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(CaCert)
	keyPair, _ := tls.X509KeyPair(ClientCert, ClientKey)
	return &tls.Config{
		// Elkeid has removed ServerName while InsecureSkipVerify is introduced.
		// ServerName: host,
		// Skip the verification step, by useing the VerifyPeerCertificate. In
		// production environment, use `InsecureSkipVerify` with combination
		// with `VerifyConnection` or `VerifyPeerCertificate`
		//
		// In Elkeid, InsecureSkipVerify is always true.
		InsecureSkipVerify: InsecureTLS,
		RootCAs:            certPool,
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{keyPair},
		// Enforce the client cerificate during the handshake (server related)
		// This is different with kolide/launcher since cert is always required
		// in Elkeid/Hades.
		ClientAuth: tls.RequireAndVerifyClientCert,
		// Verify certificate by function, avoid MITM
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			zap.S().Info("grpc tls verify cert start")
			certs := make([]*x509.Certificate, len(rawCerts))
			// Totally by Elkeid, have not checked yet
			// get asn1 data from the server certs
			for i, asn1Data := range rawCerts {
				cert, err := x509.ParseCertificate(asn1Data)
				if err != nil {
					return errors.New("tls: failed to parse certificate from server: " + err.Error())
				}
				certs[i] = cert
			}
			opts := x509.VerifyOptions{
				Roots:         certPool,
				DNSName:       host,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := certs[0].Verify(opts)
			if err != nil {
				zap.S().Errorln(err)
			}
			return err
		},
	}
}
