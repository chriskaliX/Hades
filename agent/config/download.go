package config

type Download struct {
	Version string `json:"Version"`
	Url     string `json:"Url"`
	Sha256  string `json:"Sha256"`
}
