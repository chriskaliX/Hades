package utils

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/rs/xid"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func GenerateSession() string {
	return fmt.Sprintf("session-%s-%s", xid.New(), xid.New())
}
