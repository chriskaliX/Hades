//go:build windows

package config

const (
	HADES_HOME       = "\\Program Files\\hades\\"
	HADES_PIDPATH    = HADES_HOME
	HADES_LOGHOME    = HADES_HOME + "log\\"
	HADES_MACHINE_ID = HADES_HOME + "machine-id"
)
