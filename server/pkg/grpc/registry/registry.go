// ServiceRegistry
//
// This package is invalid for now. It will be updated once
// a look-aside LB is implemented in Hades
package registry

type ServiceRegistry struct {
	AgentID         string   `json:"agentid"`
	PrivateIpv4     []string `json:"privateipv4"`
	PrivateIpv6     []string `json:"privateipv6"`
	Platform        string   `json:"platform"`
	PlatformFamily  string   `json:"platformfamily"`
	PlatformVersion string   `json:"platformversion"`
	KernelVersion   string   `json:"kernelversion"`
	CreateAt        int      `json:"createat"`
	EndAt           int      `json:"endat"`
	Version         string   `json:"version"`
	Online          bool     `json:"online"`
}

func (s *ServiceRegistry) Regist() {}

func (s *ServiceRegistry) Quit() {}
