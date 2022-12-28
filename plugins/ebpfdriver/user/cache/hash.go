package cache

import (
	"hades-ebpf/utils"

	"github.com/chriskaliX/SDK/util/hash"
)

var DefaultHashCache = hash.NewWithClock(utils.Clock)
