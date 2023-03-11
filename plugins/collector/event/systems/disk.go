package systems

import (
	"collector/eventmanager"
	"strconv"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/shirou/gopsutil/v3/disk"
)

type Disk struct{}

func (Disk) DataType() int { return 3010 }

func (Disk) Name() string { return "disk" }

func (Disk) Flag() eventmanager.EventMode { return eventmanager.Periodic }

func (Disk) Immediately() bool { return false }

func (d Disk) Run(s SDK.ISandbox, sig chan struct{}) (err error) {
	// Only physical disks information is collected
	partitions, err := disk.Partitions(false)
	if err != nil {
		return err
	}
	for _, partition := range partitions {
		usage, err := disk.Usage(partition.Mountpoint)
		if err != nil {
			continue
		}
		serial, _ := disk.SerialNumber(partition.Mountpoint)
		label, _ := disk.Label(partition.Mountpoint)
		s.SendRecord(&protocol.Record{
			DataType:  int32(d.DataType()),
			Timestamp: time.Now().Unix(),
			Data: &protocol.Payload{
				Fields: map[string]string{
					"device":     partition.Device,
					"fs_type":    partition.Fstype,
					"mountpoint": partition.Mountpoint,
					"total":      strconv.FormatUint(usage.Total, 10),
					"used":       strconv.FormatUint(usage.Used, 10),
					"free":       strconv.FormatUint(usage.Free, 10),
					"usage":      strconv.FormatFloat(usage.UsedPercent, 'f', 8, 64),
					"serial":     serial,
					"label":      label,
				},
			},
		})
	}
	return
}

func init() { addEvent(&Disk{}, 24*time.Hour) }
