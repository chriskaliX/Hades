package config

import "errors"

// 白名单, 每个主机支持64个白名单(性能问题), 支持对
// 任意collection的任意字段, 进行组和的 contains,regexp 判断
// 相当于一个规则, 引用小范围的配置规则引擎, 支持字段之间的 AND/OR
// 为什么要这么做? 以下场景:

/*
	常见的使用场景:
	某机器上因为定期执行任务, 经常会执行 ls cd dirname 等无效指令,
	但是我们不能直接进行过滤, 因为我们无法判断这些执行文件是否被替换了
	(如一些入侵的场景下, 替换了我们的指令), 所以有一个基础的组合判断场景
	如果执行路径为 /usr/bin/ls, 且其 hash 为 xxxxxx(健康, 正常)
	那么我们认定这是一次正常的执行, 过滤掉
*/

type WhiteListConfig struct {
	Config map[string]interface{}
}

func (w *WhiteListConfig) Check() (err error) {
	if w.Config != nil {
		// 作用域加载, 过滤哪个事件
		// 对应情况看 DOCS.md
		field, ok := w.Config["field"]
		if !ok {
			err = errors.New("field not found")
			return
		}
		

	}
	err = errors.New("config nil")
	return
}
