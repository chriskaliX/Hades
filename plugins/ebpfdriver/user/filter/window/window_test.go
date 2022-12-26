package window

import (
	"testing"
)

func TestWindow(t *testing.T) {
	// test for exe
	exe := NewExeWindow()
	exelist := make([]string, 0)
	for i := 0; i < 10000; i++ {
		exelist = append(exelist, "/tmp/test")
	}
	counter := 0
	for _, exework := range exelist {
		if WindowCheck(exework, exe) {
			counter += 1
		}
	}
	if counter != 9000 {
		t.Error("exe test failed, count:", counter)
	}
	// test for argv
	argv := NewArgvWindow()
	argvlist := make([]string, 0)
	for i := 0; i < 10000; i++ {
		argvlist = append(argvlist, "/usr/bin/whomai")
	}
	counter = 0
	for _, argvwork := range argvlist {
		if WindowCheck(argvwork, argv) {
			counter += 1
		}
	}
	if counter != 1500 {
		t.Error("argv test failed, count:", counter)
	}
	t.Log("window test pass")
}
