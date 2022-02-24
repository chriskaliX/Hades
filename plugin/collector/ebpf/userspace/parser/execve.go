package parser

import (
	"collector/model"
	"fmt"
	"io"
	"strings"
)

func Execve(buf io.Reader, process *model.Process) (err error) {
	// debug code here
	defer func() {
		fmt.Println(process.Exe)
		fmt.Println(process.Cwd)
		fmt.Println(process.TTYName)
		fmt.Println(process.Stdin)
	}()
	if process.Exe, err = ParseStr(buf); err != nil {
		return
	}
	if process.Cwd, err = ParseStr(buf); err != nil {
		return
	}
	if process.TTYName, err = ParseStr(buf); err != nil {
		return
	}
	if process.Stdin, err = ParseStr(buf); err != nil {
		return
	}
	if process.Stdout, err = ParseStr(buf); err != nil {
		return
	}
	if process.RemotePort, process.RemoteAddr, err = ParseRemoteAddr(buf); err != nil {
		return
	}
	// pid_tree
	pid_tree := make([]string, 0)
	if pid_tree, err = ParsePidTree(buf); err != nil {
		return
	}
	process.PidTree = strings.Join(pid_tree, "<")
	// 开始读 argv
	argsArr, err := ParseStrArray(buf)
	if err != nil {
		fmt.Println(err)
		return
	}
	// defer strArrPool.Put(argsArr)
	process.Cmdline = strings.Join(argsArr, " ")
	var envs []string
	// 开始读 envs
	if envs, err = ParseStrArray(buf); err != nil {
		return
	}

	for _, env := range envs {
		if strings.HasPrefix(env, "SSH_CONNECTION=") {
			process.SSH_connection = strings.TrimLeft(env, "SSH_CONNECTION=")
		} else if strings.HasPrefix(env, "LD_PRELOAD=") {
			process.LD_Preload = strings.TrimLeft(env, "LD_PRELOAD=")
		} else if strings.HasPrefix(env, "LD_LIBRARY_PATH=") {
			process.LD_Library_Path = strings.TrimLeft(env, "LD_LIBRARY_PATH=")
		}
	}

	if len(process.SSH_connection) == 0 {
		process.SSH_connection = "-1"
	}
	if len(process.LD_Preload) == 0 {
		process.LD_Preload = "-1"
	}
	if len(process.LD_Library_Path) == 0 {
		process.LD_Library_Path = "-1"
	}

	return
}
