package cache

import (
	"os"
	"strconv"
	"testing"

	"github.com/chriskaliX/SDK/config"
	"github.com/stretchr/testify/assert"
)

func TestArgvCache(t *testing.T) {
	cache := NewArgvCache()
	argv := cache.Get(uint32(os.Getpid()))
	if len(argv) <= 20 {
		t.Fatal("argv too short")
	}
	var invalid bool
	var overrate bool
	for i := 0; i < 500; i++ {
		argv = cache.Get(uint32(i))
		if argv == config.FieldInvalid {
			invalid = true
		}
		if argv == config.FieldOverrate {
			overrate = true
		}
	}
	if !invalid {
		t.Fatal("invalid error")
	}
	if !overrate {
		t.Fatal("overrate error")
	}
	test_string := "this is a test string"
	cache.Set(uint32(1), test_string)
	if cache.Get(uint32(1)) != test_string {
		t.Fatal("argv sets fail")
	}
	// get failed
	assert.Equal(t, cache.Get(uint32(0)), config.FieldInvalid)
}

func TestNsCache(t *testing.T) {
	var res string

	cache := NewNsCache()
	var rootPns uint32
	if pns, err := os.Readlink("/proc/1/ns/pid"); err == nil {
		if len(pns) >= 6 {
			pns, _ := strconv.Atoi(pns[5 : len(pns)-1])
			rootPns = uint32(pns)
		}
	}
	if cache.Get(uint32(1), rootPns) != config.FieldInvalid {
		t.Fatal("pid 1 cache fails")
	}

	var overrate bool
	for i := 0; i < 500; i++ {
		res = cache.Get(uint32(1), uint32(i))
		if res == config.FieldOverrate {
			overrate = true
		}
	}

	if !overrate {
		t.Fatal("ns override fails")
	}
}

func TestUserCache(t *testing.T) {
	cache := NewUserCache()
	username := cache.Get(uint32(0))
	if username != "root" {
		t.Log("username test failed")
	}
}
