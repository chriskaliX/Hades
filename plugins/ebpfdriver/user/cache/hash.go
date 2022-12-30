package cache

import (
	"hades-ebpf/utils"

	"github.com/chriskaliX/SDK/utils/hash"
)

var DefaultHashCache = hash.NewWithClock(utils.Clock)
