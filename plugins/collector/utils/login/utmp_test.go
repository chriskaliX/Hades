package login

import (
	"testing"
)

func TestRead(t *testing.T) {
	u := UtmpFile{}
	t.Log(u.GetRecord())
}
