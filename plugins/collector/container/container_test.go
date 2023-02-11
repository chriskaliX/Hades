package container

import "testing"

func TestContainer(t *testing.T) {
	containers, _ := DefaultClient.Containers()
	t.Logf("%#v", containers)
}
