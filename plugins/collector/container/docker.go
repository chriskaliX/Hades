package container

import (
	"collector/cache/process"
	"context"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

const dockerLimit = 10000

type docker struct{}

var _ Runtime = (*docker)(nil)

func (c *docker) Runtime() string { return "docker" }

func (c *docker) Containers(ctx context.Context) ([]Container, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	defer cli.Close()
	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{
		All:   true,
		Limit: dockerLimit,
	})
	if err != nil {
		return nil, err
	}
	var cs = make([]Container, 0)
	var p process.Process
	for _, container := range containers {
		c := Container{
			ID:        container.ID,
			Names:     container.Names,
			ImageID:   strings.TrimPrefix(container.ImageID, "sha256:"),
			ImageName: container.Image,
			Created:   container.Created,
			State:     container.State,
			Status:    container.Status,
			Labels:    container.Labels,
		}
		time.Sleep(50 * time.Millisecond)
		// Inspect into the container
		json, err := cli.ContainerInspect(ctx, container.ID)
		if err != nil {
			goto Next
		}
		if !json.State.Running {
			goto Next
		}
		c.PID = uint32(json.State.Pid)
		if c.PID == 0 {
			goto Next
		}
		p = process.Process{PID: int(c.PID)}
		if err := p.GetNs(); err == nil {
			c.Pns = uint32(p.Pns)
		}
	Next:
		cs = append(cs, c)
	}
	return cs, nil
}

func init() {
	registRuntime(&docker{})
}
