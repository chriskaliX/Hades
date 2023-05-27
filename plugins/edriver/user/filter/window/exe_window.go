package window

import (
	"strings"
	"time"
)

const (
	// limit tps=9000/60 = 150, just like elkeid
	exeDynQuota = 9000
	exeDuration = 60 * time.Second
	exeSize     = 1024
)

var DefaultExeWindow = NewExeWindow()

// Force check in compile-time
var _ IWindow = (*ExeWindow)(nil)

// Exe Dynamic window
type ExeWindow struct {
	Window
}

func NewExeWindow() *ExeWindow {
	w := &ExeWindow{
		Window: *NewWindow(exeDynQuota, exeDuration, exeSize),
	}
	return w
}

// Exe Filter, just like elkeid, skip those command with specific prefix
// skip with some system widely used command, like bash. also skip the
// empty or error value
func (e *ExeWindow) Filter(input string) bool {
	if strings.HasPrefix(input, "/bin") ||
		strings.HasPrefix(input, "/sbin/") ||
		strings.HasPrefix(input, "/usr/bin/") ||
		strings.HasPrefix(input, "/usr/sbin/") ||
		strings.HasPrefix(input, "-") ||
		input == "" {
		return true
	}
	return false
}
