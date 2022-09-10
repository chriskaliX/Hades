package server

import "testing"

type ConfigTest struct {
	Name         string
	Type         string
	Version      string
	Sha256       string
	Signature    string
	DownloadUrls []string
	Detail       string
}

func TestParseConfig(t *testing.T) {
	config := ConfigTest{
		Name:         "configname",
		Type:         "configrun",
		Version:      "1.0.0",
		Sha256:       "sha",
		Signature:    "sig",
		DownloadUrls: []string{"www.google.com/1", "www.google.com/2"},
		Detail:       "debug",
	}
	t.Log(parseConfig(config))
}
