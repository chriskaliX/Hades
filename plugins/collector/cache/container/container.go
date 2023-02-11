package container

import "k8s.io/utils/lru"

var Cache = lru.New(1024)

// Thread-safe get container_info by pns
func ContainerInfo(pns uint32) (containerInfo map[string]string, ok bool) {
	var index any
	index, ok = Cache.Get(pns)
	if !ok {
		return
	}
	return index.(map[string]string), ok
}
