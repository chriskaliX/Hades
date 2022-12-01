package namepsace

import (
	"collector/cache"
	"os"
	"reflect"
	"testing"
)

func assertEqual(t *testing.T, expected, actual interface{}) {
	var equal bool
	if expected == nil || actual == nil {
		equal = expected == actual
	} else {
		equal = reflect.DeepEqual(expected, actual)
	}
	if !equal {
		t.Errorf("%v != %v", expected, actual)
	}
}

func TestNsCache(t *testing.T) {
	pod, node := Cache.Get(1, uint32(cache.RootPns))
	hostname, _ := os.Hostname()
	assertEqual(t, pod, "-1")
	assertEqual(t, node, hostname)
}
