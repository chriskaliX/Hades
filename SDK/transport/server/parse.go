package server

import "encoding/json"

//
type Config struct {
	Name         string
	Type         string
	Version      string
	Sha256       string
	Signature    string
	DownloadUrls []string
	Detail       string
}

func parseConfig(config interface{}) (conf Config, err error) {
	var _byte []byte
	c := &Config{}
	_byte, err = json.Marshal(config)
	if err != nil {
		return
	}
	err = json.Unmarshal(_byte, c)
	conf = *c
	return
}
