package event

import (
	"debug/elf"
	"errors"
	"fmt"
	"hades-ebpf/userspace/decoder"
	"os"
	"path/filepath"
	"strings"

	manager "github.com/ehids/ebpfmanager"
)

var DefaultReadline = &Readline{}

var _ decoder.Event = (*Readline)(nil)

const bashBinary = "/bin/bash"

type Readline struct {
	Exe        string `json:"-"`
	Line       string `json:"line"`
	TTYName    string `json:"ttyname"`
	Stdin      string `json:"stdin"`
	Stout      string `json:"stout"`
	PidTree    string `json:"pidtree"`
	RemotePort string `json:"remoteport"`
	RemoteAddr string `json:"remoteaddr"`
	Cwd        string `json:"cwd"`
}

func (Readline) ID() uint32 {
	return 2000
}

func (Readline) String() string {
	return "readline"
}

func (r *Readline) GetExe() string {
	return r.Exe
}

func (r *Readline) Parse() (err error) {
	if r.Exe, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if r.Line, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if r.TTYName, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if r.Stdin, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if r.Stout, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	if r.RemotePort, r.RemoteAddr, err = decoder.DefaultDecoder.DecodeRemoteAddr(); err != nil {
		return
	}
	if r.PidTree, err = decoder.DefaultDecoder.DecodePidTree(); err != nil {
		return
	}
	if r.Cwd, err = decoder.DefaultDecoder.DecodeString(); err != nil {
		return
	}
	return
}

// TODO: just under test, will be updated.
// Works fine for now.
func (r Readline) checkLibray() (libpath string, err error) {
	elfFile, err := elf.Open(bashBinary)
	if err != nil {
		return
	}
	libs, err := elfFile.ImportedLibraries()
	if err != nil {
		return
	}

	var libname string

	for _, lib := range libs {
		// contains is available in go 1.18
		// if strings.Contains(lib, "libreadline.so") {
		// }
		if strings.HasPrefix(lib, "libreadline.so") {
			libname = lib
		}
	}
	if libname == "" {
		err = errors.New("No libreadline.so is found, use /bin/bash")
		return
	}
	var paths = GetDynLibDirs()
	for _, entry := range paths {
		path := filepath.Join(entry, libname)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			return path, nil
		}
	}
	return
}

// For getting the offset of the readline function, we have to go through the bash
// elf. If the function can't be found in /bin/bash or other bashes, use ldd to find
// the libreadline.so function
// @Reference: https://github.com/iovisor/bcc/blob/bc89fcec83c344b8ac961c632509f7a8304d84f8/libbpf-tools/bashreadline.c
// In BCC, just use bash `ldd /bin/bash`, but it seems not elegant in golang... so we
// try to do it. ldd is a bash script which based on ld-linux.so
// https://www.cnblogs.com/AndyJee/p/3835092.html
func (r Readline) GetProbe() []*manager.Probe {
	// find libreadline.so firstly
	_path, err := r.checkLibray()
	if err != nil {
		_path = bashBinary
	}
	fmt.Println(_path)
	// go back to /bin/bash since there is no libreadline.so here
	return []*manager.Probe{
		{
			Section:          "uretprobe/bash_readline",
			EbpfFuncName:     "uretprobe_bash_readline",
			AttachToFuncName: "readline",
			BinaryPath:       _path,
		},
	}
}

func init() {
	decoder.Regist(DefaultReadline)
}
