// Container contains the caches & functions of running containers
package container

import (
	"context"
	"errors"
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
	PID uint32 `json:"pid"`
	Pns uint32 `json:"pns"`
	// Container related fields
	ID        string            `json:"id"`
	Names     []string          `json:"names"`
	ImageName string            `json:"image_name"`
	ImageID   string            `json:"image_id"`
	Created   int64             `json:"created"`
	State     string            `json:"state"`
	Status    string            `json:"status"`
	Labels    map[string]string `json:"labels"`
	// Fields to differ the runtime
	Runtime string `json:"runtime"`
	// Additional fields for different CRI
	Endpoint string `json:"endpoint"` // Endpoint for CRI
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
			if value.Pns > 0 {
				container.Cache.Add(value.Pns, map[string]string{
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
