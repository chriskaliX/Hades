package event

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"ncp/utils"

	"github.com/chriskaliX/SDK/utils/hash"
	"k8s.io/utils/lru"
)

const maxCmdline = 512
const userHz = 100
const maxPidTrace = 4
const defaultValue = "-1"

var bootTime = uint64(0)
var rootPns uint32

var (
	argvCache = lru.New(8192)
	commCache = lru.New(8192)
	nsCache   = lru.New(8192)
	userCache = lru.New(8192)
	pidCache  = lru.New(8192)
	fileCache = hash.NewWithClock(utils.Clock)
)

type Event struct {
	Name          string `json:"name"`
	Cwd           string `json:"cwd"`
	TTY           uint32 `json:"tty"`
	Stdin         string `json:"stdin"`
	Stdout        string `json:"stdout"`
	PidTree       string `json:"pid_tree"`
	Argv          string `json:"argv"`
	SSHConnection string `json:"ssh_connection"`
	LDPreload     string `json:"ld_preload"`
	StartTime     uint64 `json:"starttime"`
	CgroupID      uint64 `json:"cgroupid"`
	Pns           uint32 `json:"pns"`
	RootPns       uint32 `json:"root_pns"`
	Pid           uint32 `json:"pid"`
	Tid           uint32 `json:"tid"`
	Uid           int    `json:"uid"`
	Gid           int    `json:"gid"`
	Ppid          uint32 `json:"ppid"`
	Pgid          uint32 `json:"pgid"`
	SessionID     uint32 `json:"sessionid"`
	Comm          string `json:"comm"`
	PComm         string `json:"pcomm"`
	// Nodename      string `json:"nodename"`
	ExeHash  string `json:"exe_hash"`
	Username string `json:"username"`
	Exe      string `json:"exe"`
	PpidArgv string `json:"ppid_argv"`
	PgidArgv string `json:"pgid_argv"`
	PodName  string `json:"pod_name"`
}

func (e *Event) GetInfo() (err error) {
	if err = e.getCwd(); err != nil {
		return
	}
	if e.Comm, err = getComm(e.Pid); err != nil {
		return
	}
	if e.Argv, err = getArgv(e.Pid); err != nil {
		return
	}
	if err = e.getExe(); err != nil {
		return
	}
	e.getExeHash()
	if err = e.getPns(); err != nil {
		return
	}
	if err = e.getEnviron(); err != nil {
		return
	}
	if err = e.getStat(); err != nil {
		return
	}
	if err = e.getStatus(); err != nil {
		return
	}
	if err = e.getUserName(); err != nil {
		return
	}
	if e.PgidArgv, err = getArgv(e.Pgid); err != nil {
		return
	}
	if e.PComm, err = getComm(e.Ppid); err != nil {
		return
	}
	if e.PpidArgv, err = getArgv(e.Ppid); err != nil {
		return
	}
	e.Stdin, _ = e.getFd(0)
	e.Stdout, _ = e.getFd(1)
	e.getPidTree()
	return
}

func (e *Event) Reset() {
	e.PidTree, e.RootPns = "", rootPns
	e.Name, e.Cwd = defaultValue, defaultValue
	e.Stdin, e.Stdout, e.Argv = defaultValue, defaultValue, defaultValue
	e.SSHConnection, e.LDPreload = defaultValue, defaultValue
	e.StartTime, e.CgroupID, e.Pns, e.Pid, e.Tid, e.Uid, e.Gid = 0, 0, 0, 0, 0, -1, -1
	e.Ppid, e.Pgid, e.SessionID, e.TTY = 0, 0, 0, 0
	e.Comm, e.PComm, e.ExeHash, e.Username = defaultValue, defaultValue, defaultValue, defaultValue
	e.Exe, e.PpidArgv, e.PgidArgv, e.PodName = defaultValue, defaultValue, defaultValue, defaultValue

}

func (e *Event) getCwd() (err error) {
	e.Cwd, err = os.Readlink("/proc/" + strconv.Itoa(int(e.Pid)) + "/cwd")
	return
}

func (e *Event) getExe() (err error) {
	e.Exe, err = os.Readlink("/proc/" + strconv.Itoa(int(e.Pid)) + "/exe")
	return
}

func (e *Event) getPns() (err error) {
	pns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", e.Pid))
	if err != nil {
		return err
	}
	if len(pns) >= 6 {
		pns, _ := strconv.Atoi(pns[5 : len(pns)-1])
		e.Pns = uint32(pns)
	}
	return
}

func (e *Event) getStat() (err error) {
	var stat []byte
	if stat, err = os.ReadFile(fmt.Sprintf("/proc/%d/stat", e.Pid)); err != nil {
		return
	}
	fields := strings.Fields(string(stat))
	if len(fields) < 24 {
		err = errors.New("invalid stat format")
		return
	}
	if len(fields[1]) > 1 {
		_ = string(fields[1][1 : len(fields[1])-1])
	}
	var field int
	field, _ = strconv.Atoi(fields[3])
	e.Ppid = uint32(field)
	field, _ = strconv.Atoi(fields[3])
	e.Pgid = uint32(field)
	field, _ = strconv.Atoi(fields[5])
	e.SessionID = uint32(field)
	field, _ = strconv.Atoi(fields[6])
	e.TTY = uint32(field)
	e.StartTime, _ = strconv.ParseUint(fields[21], 10, 64)
	e.StartTime = bootTime + (e.StartTime / userHz)
	return
}

func (e *Event) getFd(index int) (res string, err error) {
	file, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", e.Pid, index))
	if len(file) > maxCmdline {
		file = file[:maxCmdline-1]
	}
	return file, err
}

func (e *Event) getEnviron() (err error) {
	var source []byte
	source, err = os.ReadFile(fmt.Sprintf("/proc/%d/environ", e.Pid))
	if err != nil {
		return
	}
	if value, ok := nsCache.Get(e.Pns); ok {
		e.PodName = value.(string)
	}
	envs := bytes.Split(source, []byte{0})
	for index, env := range envs {
		if index >= 31 {
			break
		}
		_env := strings.Split(string(env), "=")
		if len(_env) != 2 {
			continue
		}
		if len(e.SSHConnection) <= 2 && _env[0] == "SSH_CONNECTION" {
			e.SSHConnection = _env[1]
		} else if len(e.LDPreload) <= 2 && _env[0] == "LD_PRELOAD" {
			e.LDPreload = _env[1]
		} else if len(e.PodName) <= 2 && (_env[0] == "POD_NAME" || _env[0] == "MY_POD_NAME") {
			e.PodName = _env[1]
			if e.Pns != 0 {
				nsCache.Add(e.Pns, e.PodName)
			}
		}
	}
	return
}

func (e *Event) getStatus() (err error) {
	var file *os.File
	if file, err = os.Open(fmt.Sprintf("/proc/%d/status", e.Pid)); err != nil {
		return
	}
	defer file.Close()
	s := bufio.NewScanner(file)
	for s.Scan() {
		if strings.HasPrefix(s.Text(), "Name:") {
			e.Name = strings.Fields(s.Text())[1]
		} else if strings.HasPrefix(s.Text(), "Uid:") {
			fields := strings.Fields(s.Text())
			e.Uid, _ = strconv.Atoi(fields[1])
			break
		}
	}
	return
}

func (e *Event) getUserName() (err error) {
	var usr *user.User
	if u, ok := userCache.Get(e.Uid); ok {
		usr = u.(*user.User)
		if e.Gid, err = strconv.Atoi(usr.Gid); err != nil {
			return
		}
		e.Username = usr.Username
		return
	}
	if usr, err = user.LookupId(strconv.FormatInt(int64(e.Uid), 10)); err != nil {
		return err
	}
	e.Username = usr.Username
	if e.Gid, err = strconv.Atoi(usr.Gid); err != nil {
		return err
	}
	userCache.Add(e.Uid, usr)
	return nil
}

func (e *Event) getExeHash() {
	if len(e.Exe) <= 2 {
		return
	}
	e.ExeHash = fileCache.GetHash(e.Exe)
}

func (e *Event) getPidTree() {
	var first = true
	pid := e.Tid
	for i := 0; i < maxPidTrace; i++ {
		e.PidTree = fmt.Sprintf("%s%d.", e.PidTree, pid)
		if cmdline, ok := commCache.Get(pid); ok {
			e.PidTree = e.PidTree + cmdline.(string)
			goto PidLoop
		}
		// every event get one chance to flash the comm if a pid was found
		if first {
			first = false
			if comm, err := getComm(pid); err == nil {
				e.PidTree = e.PidTree + comm
				goto PidLoop
			}
		}
		break
	PidLoop:
		if pid <= 2 {
			break
		}
		if ppid, ok := pidCache.Get(pid); ok {
			pid = ppid.(uint32)
			e.PidTree = e.PidTree + "<"
		} else {
			break
		}
	}
	e.PidTree = strings.TrimRight(e.PidTree, "<")
}

func getArgv(pid uint32) (argv string, err error) {
	if value, ok := argvCache.Get(pid); ok {
		argv = value.(string)
	}
	var res []byte
	if res, err = os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err != nil {
		return
	}
	if len(res) == 0 {
		return
	}
	res = bytes.ReplaceAll(res, []byte{0}, []byte{' '})
	res = bytes.TrimSpace(res)
	argv = string(res)
	if len(argv) > maxCmdline {
		argv = argv[:maxCmdline]
	}
	argvCache.Add(pid, argv)
	return
}

func getComm(pid uint32) (comm string, err error) {
	if value, ok := commCache.Get(pid); ok {
		comm = value.(string)
	}
	var res []byte
	if res, err = os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err != nil {
		return
	}
	if len(res) == 0 {
		return
	}
	res = bytes.TrimSpace(res)
	comm = string(res)
	commCache.Add(pid, comm)
	return
}

func getPids(limit int) (pids []int, err error) {
	pids = make([]int, 0, 1000)
	d, err := os.Open("/proc")
	if err != nil {
		return
	}
	names, err := d.Readdirnames(limit + 128)
	if err != nil {
		return
	}
	for _, name := range names {
		if limit == 0 {
			return
		}
		pid, err := strconv.ParseInt(name, 10, 64)
		if err == nil {
			pids = append(pids, int(pid))
			limit -= 1
		}
	}
	return
}

// This is the background job for filling the caches
func getProcess() {
	pids, err := getPids(1000)
	if err != nil {
		return
	}
	for _, pid := range pids {
		time.Sleep(100 * time.Millisecond)
		// comm
		if comm, err := getComm(uint32(pid)); err != nil {
			continue
		} else {
			commCache.Add(uint32(pid), comm)
		}
		// ppid
		var stat []byte
		if stat, err = os.ReadFile(fmt.Sprintf("/proc/%d/stat", uint32(pid))); err != nil {
			continue
		}
		fields := strings.Fields(string(stat))
		field, _ := strconv.Atoi(fields[3])
		pidCache.Add(uint32(pid), uint32(field))
	}
}

func init() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		init := true
		defer ticker.Stop()
		for range ticker.C {
			if init {
				ticker.Reset(10 * time.Minute)
				init = false
			}
			getProcess()
		}
	}()
	// pns
	if pns, err := os.Readlink("/proc/1/ns/pid"); err == nil {
		if len(pns) >= 6 {
			pns, _ := strconv.Atoi(pns[5 : len(pns)-1])
			rootPns = uint32(pns)
		}
	}

	file, err := os.Open("/proc/stat")
	if err != nil {
		return
	}
	defer file.Close()
	s := bufio.NewScanner(file)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if !strings.HasPrefix(s.Text(), "btime") {
			continue
		}
		if len(fields) < 2 {
			continue
		}
		bootTime, _ = strconv.ParseUint(fields[1], 10, 64)
	}
}
