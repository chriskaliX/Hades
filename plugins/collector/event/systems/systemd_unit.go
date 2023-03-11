package systems

import (
	"collector/eventmanager"
	"collector/utils"
	"strings"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/godbus/dbus/v5"
	"github.com/mitchellh/mapstructure"
)

type SystemdUnit struct {
	conn *dbus.Conn
}

type unit struct {
	Name        string `mapstructure:"name"`
	Description string `mapstructure:"description"`
	LoadState   string `mapstructure:"load_state"`
	ActiveState string `mapstructure:"active_state"`
	SubState    string `mapstructure:"sub_state"`
	Followed    string `mapstructure:"followed"`
	Path        string `mapstructure:"path"`
	JobID       string `mapstructure:"job_id"`
	JobType     string `mapstructure:"job_type"`
	JobPath     string `mapstructure:"job_path"`
}

func (SystemdUnit) DataType() int { return 3011 }

func (SystemdUnit) Name() string { return "systemd_unit" }

func (SystemdUnit) Flag() eventmanager.EventMode { return eventmanager.Periodic }

func (SystemdUnit) Immediately() bool { return false }

func (sys *SystemdUnit) Run(s SDK.ISandbox, sig chan struct{}) (err error) {
	hash := utils.Hash()
	sys.conn, err = dbus.SystemBusPrivate()
	if err != nil {
		return err
	}
	defer sys.conn.Close()
	err = sys.conn.Auth(nil)
	if err != nil {
		return err
	}
	err = sys.conn.Hello()
	if err != nil {
		return err
	}
	var units []unit
	obj := sys.conn.Object("org.freedesktop.systemd1", dbus.ObjectPath("/org/freedesktop/systemd1"))
	if err = obj.Call("org.freedesktop.systemd1.Manager.ListUnits", 0).Store(&units); err != nil {
		return
	}

	for _, u := range units {
		// For now, only get the service
		if !sys.isService(u.Name) {
			continue
		}
		data := make(map[string]string, 11)
		if err = mapstructure.Decode(u, &data); err != nil {
			continue
		}
		data["package_seq"] = hash
		s.SendRecord(&protocol.Record{
			DataType:  int32(sys.DataType()),
			Timestamp: utils.Clock.Now().Unix(),
			Data: &protocol.Payload{
				Fields: data,
			},
		})
	}
	return
}

func (SystemdUnit) isService(name string) bool {
	return strings.HasSuffix(name, ".service")
}

func init() { addEvent(&SystemdUnit{}, 24*time.Hour) }
