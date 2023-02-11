package process

import (
	"k8s.io/utils/lru"
)

const maxArgv = 2048
const maxPid = 4096

var PidCache = lru.New(maxPid)
var ArgvCache = lru.New(maxArgv)
var CmdlineCache = lru.New(maxPid)
