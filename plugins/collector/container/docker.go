package container

import (
	"bytes"
	"collector/cache/process"
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

const dockerLimit = 3000

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
		var name string
		if len(container.Names) > 0 {
			// docker may starts with prefix "/"
			name = strings.TrimPrefix(container.Names[0], "/")
		}
		label, _ := sonic.MarshalString(container.Labels)
		c := Container{
			ID:        container.ID,
			Names:     name,
			ImageID:   strings.TrimPrefix(container.ImageID, "sha256:"),
			ImageName: container.Image,
			Created:   strconv.FormatInt(container.Created, 10),
			State:     container.State,
			Status:    container.Status,
			Labels:    label,
		}
		time.Sleep(50 * time.Millisecond)
		// inspect into the container
		if json, err := cli.ContainerInspect(ctx, container.ID); err == nil {
			// the container is running
			if json.State.Pid != 0 {
				c.PID = strconv.FormatInt(int64(json.State.Pid), 10)
				p = process.Process{PID: int(json.State.Pid)}
				if err := p.GetNs(); err == nil {
					c.Pns = strconv.FormatInt(int64(p.Pns), 10)
				}
			}
		}
		cs = append(cs, c)
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
