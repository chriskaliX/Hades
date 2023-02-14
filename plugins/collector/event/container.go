package event

import (
	"collector/container"
	"collector/eventmanager"
	"collector/utils"

	"github.com/bytedance/sonic"
	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
)

var _ eventmanager.IEvent = (*Container)(nil)

type Container struct{}

func (Container) DataType() int { return 1003 }

func (Container) Name() string { return "container" }

func (Container) Flag() int { return eventmanager.Periodic }

func (Container) Immediately() bool { return true }

func (c *Container) Run(s SDK.ISandbox, sig chan struct{}) error {
	containers, err := container.DefaultClient.Containers()
	if err != nil {
		return err
	}
	for _, container := range containers {
		res, err := sonic.MarshalString(container)
		if err != nil {
			continue
		}
		s.SendRecord(&protocol.Record{
			DataType:  int32(c.DataType()),
			Timestamp: utils.Clock.Now().Unix(),
			Data: &protocol.Payload{
				Fields: map[string]string{
					// TODO: unwrap the data
					"data": res,
				},
			},
		})
	}

	return nil
}
