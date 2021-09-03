package config

type WhiteListConfig struct {
	ProcessWhiteLists []ProcessWhiteList
}

type ProcessWhiteList struct {
	Cmdline string
	PsTree  string
	Cwd     string
	Sha256  string
}

func (w *WhiteListConfig) Check() error {
	return nil
}
