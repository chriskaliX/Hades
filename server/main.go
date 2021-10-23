package main

import (
	"hadeserver/grpctrans"
	"time"
)

func main() {
	grpctrans.Run()
	time.Sleep(time.Hour)
}
