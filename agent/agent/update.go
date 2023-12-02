package agent

import (
	"github.com/chriskaliX/Hades/agent/proto"
	"github.com/chriskaliX/Hades/agent/utils"
	"context"
	"os/exec"
	"path"

	"github.com/shirou/gopsutil/v3/host"
)

var platform string

func init() {
	platform, _, _, _ = host.PlatformInformation()
}

// agent self-update
// Windows compatible is not invalid for now
func Update(config proto.Config) (err error) {
	dst := path.Join("/tmp", Product+"-updater"+".pkg")
	// unfinished
	err = utils.Download(context.Background(), dst, config.Sha256, config.DownloadUrls, config.Type)
	if err != nil {
		return
	}
	var cmd *exec.Cmd
	switch platform {
	case "debian":
		cmd = exec.Command("dpkg", "-i", dst)
	case "rhel", "fedora", "suse":
		cmd = exec.Command("rpm", "-Uvh", dst)
	default:
		// Other platform including
		// gentoo slackware arch exherbo alpine
		// coreos solus neokylin
		cmd = exec.Command(dst)
	}
	err = cmd.Run()
	return
}
