package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
)

// 也看了字节的写法, systemd 直接启一个 journalctl
// 这样写很简单, 但是感觉不优雅, 再调研一下吧, 看看有没有兼容性好一点优雅一点的
// 上传通道应该也要分开或者独立限制, 因为如果 syscall 太多导致所有日志丢失也是一个问题
func GetSSH(ctx context.Context) {
	cmd := exec.Command("journalctl", "-f", "_COMM=sshd", "-o", "json")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	err = cmd.Start()
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(stdout)
	var message []byte
	tmp := make(map[string]string)
	for scanner.Scan() {
		message = scanner.Bytes()
		err = json.Unmarshal(message, &tmp)
		// 这里 err 上传
		msg := tmp["MESSAGE"]
		switch {
		case strings.Contains(msg, "Failed password"):
			//
		case strings.Contains(msg, "Accepted password"):
			//
		}
	}
}
