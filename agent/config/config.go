package config

type IConfig interface {
	Check() error //检测配置合法性
}

// func ConfigLoad(confByte []byte, config IConfig) (IConfig, error){
// 	var confTmp IConfig
// 	confTmp = reflect.New(reflect.ValueOf(config).Elem().Type()).Interface().(IConfig)

// 	confTmpReflect := reflect.TypeOf(confTmp).Elem()
// 	confTmpReflectV := reflect.ValueOf(confTmp).Elem()

// 	configReflect := reflect.TypeOf(config).Elem()
// 	configReflectV := reflect.ValueOf(config).Elem()
// }
