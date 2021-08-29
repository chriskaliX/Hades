package network

import (
	"bufio"
	"hids-agent/utils"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func ParseProcNet(family, protocol uint8, path string, status int) (sockets []Socket, err error) {
	var file *os.File
	file, err = os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	r := bufio.NewScanner(io.LimitReader(file, 1024*1024*2))
	header := make(map[int]string)
	for i := 0; r.Scan(); i++ {
		if i == 0 {
			header[0] = "sl"
			header[1] = "local_address"
			header[2] = "rem_address"
			header[3] = "st"
			header[4] = "queue"
			header[5] = "t"
			header[6] = "retrnsmt"
			header[7] = "uid"
			for index, field := range strings.Fields(r.Text()[strings.Index(r.Text(), "uid")+3:]) {
				header[8+index] = field
			}
		} else {
			socket := Socket{Family: family, Type: protocol}
			droped := false
			for index, key := range strings.Fields(r.Text()) {
				switch header[index] {
				case "local_address":
					fields := strings.Split(key, ":")
					if len(fields) != 2 {
						droped = true
						break
					}
					socket.SIP, err = utils.ParseIP(fields[0])
					if err != nil {
						droped = true
						break
					}
					var port uint64
					port, err = strconv.ParseUint(fields[1], 16, 64)
					if err != nil {
						droped = true
						break
					}
					socket.SPort = uint16(port)
				case "rem_address":
					fields := strings.Split(key, ":")
					if len(fields) != 2 {
						droped = true
						break
					}
					socket.DIP, err = utils.ParseIP(fields[0])
					if err != nil {
						droped = true
						break
					}
					var port uint64
					port, err = strconv.ParseUint(fields[1], 16, 64)
					if err != nil {
						droped = true
						break
					}
					socket.DPort = uint16(port)
				case "st":
					st, err := strconv.ParseUint(key, 16, 64)
					if err != nil {
						continue
					}

					// 更改程 LISTEN 和建立
					if status == LISTEN {
						if (protocol == unix.IPPROTO_UDP && st != 7) || (protocol == unix.IPPROTO_TCP && st != 10) {
							droped = true
							break
						}
					} else if status == TCP_ESTABLISHED {
						if protocol == unix.IPPROTO_TCP && st != 1 {
							droped = true
							break
						}
					} else {
						droped = true
						break
					}
					socket.State = uint8(st)
				case "uid":
					uid, err := strconv.ParseUint(key, 0, 64)
					if err != nil {
						continue
					}
					socket.UID = uint32(uid)
					if user, err := user.LookupId(strconv.Itoa(int(uid))); err == nil {
						socket.Username = user.Name
					}
				case "inode":
					inode, err := strconv.ParseUint(key, 0, 64)
					if err != nil {
						continue
					}
					socket.Inode = uint32(inode)
				default:
				}
			}
			if !droped && len(socket.DIP) != 0 && len(socket.SIP) != 0 && socket.State != 0 {
				sockets = append(sockets, socket)
			}
		}

	}
	return
}
