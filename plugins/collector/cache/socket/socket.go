package socket

import (
	"collector/socket"

	"k8s.io/utils/lru"
)

var Cache = lru.New(1024)

func Get(inode uint32) (s socket.Socket, ok bool) {
	var si interface{}
	si, ok = Cache.Get(inode)
	if ok {
		return si.(socket.Socket), ok
	}
	// Add backup looping here
	return
}

func Put(inode uint32, s socket.Socket) {
	Cache.Add(inode, s)
}
