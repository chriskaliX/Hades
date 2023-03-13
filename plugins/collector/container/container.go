// Container contains the caches & functions of running containers
package container

import (
	"context"
	"errors"
	"strconv"
	"time"

	"collector/cache/container"
)

var DefaultClient = NewClient()

type ContainerStatus string

const statusRunning ContainerStatus = "running"

var timeOut = 3 * time.Minute

// The container struct fields for all SDK
type Container struct {
	// IDENTIFIER for containers
	PID string `mapstructure:"pid"`
	Pns string `mapstructure:"pns"`
	// Container related fields
	ID        string `mapstructure:"id"`
	Names     string `mapstructure:"names"`
	ImageName string `mapstructure:"image_name"`
	ImageID   string `mapstructure:"image_id"`
	Created   string `mapstructure:"created"`
	State     string `mapstructure:"state"`
	Status    string `mapstructure:"status"`
	Labels    string `mapstructure:"labels"`
	// Fields to differ the runtime
	Runtime string `mapstructure:"runtime"`
	// Additional fields for different CRI
	Endpoint string `mapstructure:"endpoint"` // Endpoint for CRI
}

// Runtime points out the functions that all runtime SDK should follow
type Runtime interface {
	Runtime() string
	Containers(ctx context.Context) ([]Container, error)
	ExecWithContext(ctx context.Context, containerID string, name string, arg ...string) ([]byte, error)
}

// The real client for searching
type Client struct {
	m map[string]Runtime
}

func NewClient() *Client {
	return &Client{
		m: make(map[string]Runtime, 0),
	}
}

// List the containers of registed runtime
func (c *Client) Containers() ([]Container, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeOut)
	defer cancel()
	var containers = make([]Container, 0)
	for _, client := range c.m {
		cs, err := client.Containers(ctx)
		if err != nil {
			// TODO: IGNORE the err rather than ignore? since once the CRI does not exist, always be none
			continue
		}
		// Fill up the runtime fields & add pns to cache
		for index, value := range cs {
			cs[index].Runtime = client.Runtime()
			if pns, err := strconv.ParseInt(value.Pns, 10, 64); err == nil && pns > 0 {
				container.Cache.Add(uint32(pns), map[string]string{
					container.ContainerId:      value.ID,
					container.ContainerName:    value.ImageName,
					container.ContainerRuntime: client.Runtime(),
				})
			}
		}
		containers = append(containers, cs...)
	}
	return containers, nil
}

func (c *Client) Exec(pns uint32, name string, args ...string) (result string, err error) {
	info, ok := container.ContainerInfo(pns)
	if !ok {
		err = errors.New("get info error")
		return
	}
	id := info[container.ContainerId]
	runtime := info[container.ContainerRuntime]
	r := c.m[runtime]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var resByte []byte
	resByte, err = r.ExecWithContext(ctx, id, name, args...)
	if err != nil {
		return
	}
	result = string(resByte)
	return
}

func registRuntime(r Runtime) {
	DefaultClient.m[r.Runtime()] = r
}
