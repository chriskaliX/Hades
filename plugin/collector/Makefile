all: build 
build:
	go build .
debug:
	go build -ldflags="-X collector/share.Env=debug" .
clean:
	rm -f collector