package user

import "testing"

func TestUser(t *testing.T) {
	user := Cache.GetUser(0)
	if user.Username != "root" || user.UID != "0" {
		t.Error("GetUser failed")
	}
	if Cache.GetUsername(0) != "root" {
		t.Error("GetUsername failed")
	}
}
