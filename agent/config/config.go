package config

type IConfig interface {
	Check() error //检测配置合法性
}
