package container

import (
	"bytes"
	"collector/cache/process"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

const dockerLimit = 10000

type docker struct {
	c *client.Client
}

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
		cs = append(cs, c)
	Next:
	}
	return cs, nil
}

// From Elkeid
func (d *docker) ExecWithContext(ctx context.Context, containerID string, name string, arg ...string) (result []byte, err error) {
	if d.c == nil {
		d.c, err = client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			return nil, err
		}
	}
	cmd := make([]string, len(arg)+1)
	cmd[0] = name
	copy(cmd[1:], arg)
	createResp, err := d.c.ContainerExecCreate(ctx, containerID, types.ExecConfig{Cmd: cmd, AttachStdout: true, AttachStderr: true})
	if err != nil {
		return nil, err
	}
	attachResp, err := d.c.ContainerExecAttach(ctx, createResp.ID, types.ExecStartCheck{})
	if err != nil {
		return nil, err
	}
	defer attachResp.Close()
	go func() {
		<-ctx.Done()
		attachResp.Close()
		// ! The process maybe still alive!
	}()
	stdout := bytes.NewBuffer(nil)
	stderr := bytes.NewBuffer(nil)
	_, err = stdcopy.StdCopy(stdout, stderr, attachResp.Reader)
	if err != nil {
		return nil, err
	}
	inspectResp, err := d.c.ContainerExecInspect(ctx, createResp.ID)
	if err == nil && inspectResp.ExitCode != 0 {
		if len(stderr.Bytes()) != 0 {
			return nil, errors.New(stderr.String())
		}
		if len(stdout.Bytes()) != 0 {
			return nil, errors.New(stdout.String())
		}
		return nil, errors.New("unknown error")
	}
	return bytes.Join([][]byte{stdout.Bytes(), stderr.Bytes()}, []byte{'\n'}), nil
}

func init() {
	registRuntime(&docker{})
}
