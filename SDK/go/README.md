# Hades SDK

> Hades SDK is a widely used toolkit for plugin dev.

## Function

- transport
- logger
- clock
- config
- util

## Examples

```go
var debug bool
flag.BoolVar(&debug, "debug", false, "set to run in debug mode")
flag.Parse()
// start the sandbox
sconfig := &SDK.SandboxConfig{
    Debug: debug,
    Hash:  true,
    Name:  "collector",
    LogConfig: &logger.Config{
        Path:        "collector.log",
        MaxSize:     10,
        MaxBackups:  10,
        Compress:    true,
        FileLevel:   zapcore.InfoLevel,
        RemoteLevel: zapcore.ErrorLevel,
    },
}

// sandbox init
sandbox := SDK.NewSandbox()
sandbox.Init(sconfig)

sandbox.Run(thefunction)
```
