package SDK

import (
	"runtime"
	"runtime/debug"
	"time"

	"go.uber.org/zap"
)

// From ilogtail
func RuntimeOpt() {
	setGCPercentForSlowStart()
	enforceGC()
}

// setGCPercentForSlowStart sets GC percent with a small value at startup
// to avoid high RSS (caused by data catch-up) to trigger OOM-kill.
// from: alibaba ilogtail
func setGCPercentForSlowStart() {
	gcPercent := 40
	defaultGCPercent := debug.SetGCPercent(gcPercent)
	zap.S().Infof("set startup GC percent from %v to %v", defaultGCPercent, gcPercent)
	resumeSeconds := 5 * 60
	go func(pc int, sec int) {
		time.Sleep(time.Second * time.Duration(sec))
		last := debug.SetGCPercent(pc)
		zap.S().Infof("resume GC percent from %v to %v", last, pc)
	}(defaultGCPercent, resumeSeconds)
}

func enforceGC() {
	go func() {
		for {
			// force gc every 3 minutes
			time.Sleep(time.Minute * 3)
			zap.S().Debug("force gc done", time.Now())
			runtime.GC()
			zap.S().Debug("force gc done", time.Now())
			debug.FreeOSMemory()
			zap.S().Debug("free os memory done", time.Now())
		}
	}()
}
