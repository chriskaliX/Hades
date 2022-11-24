//go:build linux

package config

const (
	HADES_HOME       = "/etc/hades/"
	HADES_PIDPATH    = "/var/run/"
	HADES_LOGHOME    = "/var/log/hades/"
	HADES_MACHINE_ID = HADES_HOME + "machine-id"
)
