package config

import (
	"errors"
	"strconv"
)

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
	Field string `json:"Field"`
	Rules []Rule `json:"Rules"`
}

type Rule struct {
	Order uint   `json:"Order"`
	Raw   string `json:"Raw"` //Raw字段 field:string
	Type  string `json:"Type"`
}

func (w *WhiteListConfig) Check() error {
	// 检验 config 是否存在
	if w == nil {
		return errors.New("config nil")
	}

	// 检验Field范围是否正确
	if fieldNum, err := strconv.Atoi(w.Field); err != nil {
		return err
	} else {
		if (fieldNum < 1000) || (fieldNum > 1007) {
			return errors.New("field range error")
		}
	}

	// 检验 config 数量是否正确
	if len(w.Rules)%2 == 0 || len(w.Rules) > 5 {
		return errors.New("config count error")
	}

	// 开始遍历 rules
	for _, rule := range w.Rules {
		if rule.Type != "operation" && rule.Type != "string" {
			return errors.New("raw string field")
		}
	}

	return nil
}
