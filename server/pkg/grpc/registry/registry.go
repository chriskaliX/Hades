// ServiceRegistry
//
// This package is invalid for now. It will be updated once
// a look-aside LB is implemented in Hades
package registry

type ServiceRegistry struct {
	AgentID         string   `json:"agent_id"`
	PrivateIpv4     []string `json:"private_ipv4"`
	PrivateIpv6     []string `json:"private_ipv6"`
	Platform        string   `json:"platform"`
	PlatformFamily  string   `json:"platform_family"`
	PlatformVersion string   `json:"platform_version"`
	KernelVersion   string   `json:"kernel_version"`
	CreateAt        int      `json:"create_at"`
	EndAt           int      `json:"end_at"`
	Version         string   `json:"version"`
	Online          bool     `json:"online"`
}

func (s *ServiceRegistry) Regist() {}

func (s *ServiceRegistry) Quit() {}
