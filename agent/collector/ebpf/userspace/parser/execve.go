package parser

import (
	"io"
)

func Execve(buf io.Reader) (err error) {
	return
	// var (
	// 	file        string
	// 	cwd         string
	// 	tty         string
	// 	stdin       string
	// 	stout       string
	// 	remote_port string
	// 	remote_addr string
	// 	pids        string
	// )
	// if file, err = ParseStr(buf); err != nil {
	// 	return
	// }

	// if cwd, err = ParseStr(buf); err != nil {
	// 	return
	// }

	// if tty, err = ParseStr(buf); err != nil {
	// 	return
	// }

	// if stdin, err = ParseStr(buf); err != nil {
	// 	return
	// }

	// if stout, err = ParseStr(buf); err != nil {
	// 	return
	// }

	// if remote_port, remote_addr, err = parseRemoteAddr(buf); err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// // pid_tree
	// pid_tree := make([]string, 0)
	// if pid_tree, err = ParsePidTree(buf); err != nil {
	// 	return
	// }
	// pids = strings.Join(pid_tree, "<")
	// // 开始读 argv
	// argsArr, err := ParseStrArray(buf)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// // defer strArrPool.Put(argsArr)
	// args = strings.Join(argsArr, " ")
	// // 开始读 envs
	// if envs, err = parser.ParseStrArray(buf); err != nil {
	// 	return
	// }
	// return
}
