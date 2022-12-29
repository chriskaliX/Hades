package process

import (
	"os"
	"testing"
)

func TestGetPids(t *testing.T) {
	a := func(limit int) {
		if pids, err := GetPids(limit); err != nil || len(pids) != limit {
			t.Log(len(pids))
			t.Error("GetPids failed")
		}
	}
	a(1)
	a(20)
	a(30)
}

func TestProcess(t *testing.T) {
	var err error
	proc := Process{}
	proc.PID = os.Getpid()

	if err = proc.GetStatus(); err != nil {
		t.Error(err)
		return
	}
	if err = proc.GetCwd(); err != nil {
		t.Error(err)
		return
	}
	if err = proc.GetCmdline(); err != nil {
		t.Error(err)
		return
	}
	if err := proc.GetCwd(); err != nil {
		t.Error(err)
		return
	}
	if err = proc.GetCmdline(); err != nil {
		t.Error(err)
		return
	}
	if err = proc.GetExe(); err != nil {
		t.Error(err)
		return
	}
	if err = proc.GetComm(); err != nil {
		t.Error(err)
		return
	}
	if err = proc.GetNs(); err != nil {
		t.Error(err)
		return
	}
	if proc.Stdin, err = getFd(proc.PID, 0); err != nil {
		t.Error(err)
		return
	}
	if proc.Stdout, err = getFd(proc.PID, 0); err != nil {
		t.Error(err)
		return
	}
	if err = proc.GetStat(false); err != nil {
		t.Error(err)
		return
	}
}

func TestGetFds(t *testing.T) {
	pid := os.Getpid()
	strs, err := GetFds(pid)
	if err != nil {
		t.Error(err)
		return
	}
	if len(strs) < 2 {
		t.Error("GetFds return error:", strs)
		return
	}
}
