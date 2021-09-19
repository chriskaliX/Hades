package config

type IConfig interface {
	Check() error //检测配置合法性
	Load(confByte []byte) (error)
}

// func ConfigLoad(confByte []byte, config IConfig) (IConfig, error) {
// 	//反射生成临时的IConfig
// 	var confTmp IConfig
// 	confTmp = reflect.New(reflect.ValueOf(config).Elem().Type()).Interface().(IConfig)

// 	//反射 confTmp 的属性
// 	confTmpReflect := reflect.TypeOf(confTmp).Elem()
// 	confTmpReflectV := reflect.ValueOf(confTmp).Elem()

// 	//反射config IConfig
// 	configReflect := reflect.TypeOf(config).Elem()
// 	configReflectV := reflect.ValueOf(config).Elem()

// 	for i := 0; i < num; i++ {
// 		//遍历处理每个Field
// 		envStructTmp := configReflect.Field(i)
// 		//根据配置中的项，来覆盖默认值
// 		if envStructTmp.Type == confStructTmp.Type {
// 			configReflectV.FieldByName(envStructTmp.Name).Set(confTmpReflectV.Field(i))
// 		}
// 	}
// 	return nil, nil
// }
