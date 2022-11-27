# H-boat

> The server side for Hades, it's under development for now

## Quick Start

编译

```bash
make
```

启动 grpc

```bash
./hboat grpc --addr <you address> --port <your port>
```

默认在本地还会启动一个 web (127.0.0.1:7811)

接口如下:

```bash
agentID 查询:

curl http://127.0.0.1:7811/api/v1/grpc/all


插件下发:

curl "http://127.0.0.1:7811/api/v1/grpc/config?agentid=<agentid>&name=<plugin_name>&sha256=<sha256>&downloadurl=<downloadurl>&version=<version>"

如果支持 BTF, 可以直接使用 https://github.com/chriskaliX/Hades/releases/download/v1.0.0/eBPF-Driver-v1.0.0
```
