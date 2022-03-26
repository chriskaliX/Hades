package agent

import (
	"agent/host"
	"agent/proto"
	"agent/utils"
	"context"
	"os/exec"
	"path"
)

// agent self-update
func Update(config proto.Config) (err error) {
	dst := path.Join("/tmp", Product+"-updater"+".pkg")
	// unfinished
	err = utils.Download(context.Background(), dst, config.Sha256, config.DownloadUrls, config.Type)
	if err != nil {
		return
	}
	var cmd *exec.Cmd
	switch host.PlatformFamily {
	// 为了后续兼容性，先不合并debian与default分支
	case "debian":
		cmd = exec.Command("dpkg", "-i", dst)
	// ref:https://docs.fedoraproject.org/ro/Fedora_Draft_Documentation/0.1/html/RPM_Guide/ch-command-reference.html
	case "rhel", "fedora", "suse":
		cmd = exec.Command("rpm", "-Uvh", dst)
	default:
		cmd = exec.Command("dpkg", "-i", dst)
	}
	err = cmd.Run()
	return
}
