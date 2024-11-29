package cache

import (
	"edriver/utils"

	"github.com/chriskaliX/SDK/utils/hash"
)

var DefaultHashCache = hash.NewWithClock(utils.Clock)
