package main

import (
	_ "hboat/cmd/grpc"
	"hboat/cmd/root"
	"log"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix | log.Lshortfile)
	root.Execute()
}
