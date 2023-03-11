package event

import (
	"collector/container"
	"collector/eventmanager"
	"collector/utils"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/mitchellh/mapstructure"
)

var _ eventmanager.IEvent = (*Container)(nil)

type Container struct{}

func (Container) DataType() int { return 3018 }

func (Container) Name() string { return "container" }

func (Container) Flag() eventmanager.EventMode { return eventmanager.Periodic }

func (Container) Immediately() bool { return true }

func (c *Container) Run(s SDK.ISandbox, sig chan struct{}) error {
	hash := utils.Hash()
	containers, err := container.DefaultClient.Containers()
	if err != nil {
		return err
	}
	for _, container := range containers {
		rec := &protocol.Record{
			DataType:  int32(c.DataType()),
			Timestamp: utils.Clock.Now().Unix(),
			Data: &protocol.Payload{
				Fields: make(map[string]string, 13),
			},
		}
		mapstructure.Decode(&container, &rec.Data.Fields)
		rec.Data.Fields["package_seq"] = hash
		s.SendRecord(rec)
	}
	return nil
}
