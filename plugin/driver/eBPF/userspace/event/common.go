package event

import (
	"bufio"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap/buffer"
)

var (
	bytepool buffer.Pool
)

func init() {
	bytepool = buffer.NewPool()
}

func getStr(buf io.Reader, size uint32) (str string, err error) {
	buffer := bytepool.Get()
	defer buffer.Free()
	if err = binary.Read(buf, binary.LittleEndian, buffer.Bytes()[:size]); err != nil {
		return
	}
	str = string(buffer.Bytes()[:size])
	return
}

func printUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}

func Print16BytesSliceIP(in []byte) string {
	ip := net.IP(in)
	return ip.String()
}

// all down here is from ehids/ecapture, same with code in
// https://github.com/kontsevoy/godl
func GetDynLibDirs() []string {
	dirs, err := ParseDynLibConf("/etc/ld.so.conf")
	if err != nil {
		log.Println(err.Error())
		return []string{"/usr/lib64", "/lib64"}
	}
	return append(dirs, "/lib64", "/usr/lib64")
}

// ParseDynLibConf reads/parses DL config files defined as a pattern
// and returns a list of directories found in there (or an error).
func ParseDynLibConf(pattern string) (dirs []string, err error) {
	files := GlobMany([]string{pattern}, nil)

	for _, configFile := range files {
		fd, err := os.Open(configFile)
		if err != nil {
			return dirs, err
		}
		defer fd.Close()

		sc := bufio.NewScanner(fd)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			// ignore comments and empty lines
			if len(line) == 0 || line[0] == '#' || line[0] == ';' {
				continue
			}
			// found "include" directive?
			words := strings.Fields(line)
			if strings.ToLower(words[0]) == "include" {
				subdirs, err := ParseDynLibConf(words[1])
				if err != nil && !os.IsNotExist(err) {
					return dirs, err
				}
				dirs = append(dirs, subdirs...)
			} else {
				dirs = append(dirs, line)
			}
		}
	}
	return dirs, err
}

func GlobMany(targets []string, onErr func(string, error)) []string {
	rv := make([]string, 0, 20)
	addFile := func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			log.Println(err.Error())
			return err
		}
		rv = append(rv, path)
		return err
	}

	for _, p := range targets {
		// "p" is a wildcard pattern? expand it:
		if strings.Contains(p, "*") {
			matches, err := filepath.Glob(p)
			if err == nil {
				// walk each match:
				for _, p := range matches {
					filepath.Walk(p, addFile)
				}
			}
			// path is not a wildcard, walk it:
		} else {
			filepath.Walk(p, addFile)
		}
	}
	return rv
}
