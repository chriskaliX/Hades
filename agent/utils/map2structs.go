package utils

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
)

// https://my.oschina.net/u/4244677/blog/4254408
// 看滴滴的文章, 感觉挺好, 简化一下

func Bind(configMap map[string]string, result interface{}) error {
	// 被绑定的结构体非指针错误返回
	if reflect.ValueOf(result).Kind() != reflect.Ptr {
		return errors.New("input not point")
	}
	// 被绑定的结构体指针为 null 错误返回
	if reflect.ValueOf(result).IsNil() {
		return errors.New("input is null")
	}
	v := reflect.ValueOf(result).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		// map 中没该变量有则跳过
		value, ok := configMap[tag]
		if !ok {
			continue
		}
		// 跳过结构体中不可 set 的私有变量
		if !v.Field(i).CanSet() {
			continue
		}
		switch v.Field(i).Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			res, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return err
			}
			v.Field(i).SetInt(res)
		case reflect.String:
			v.Field(i).SetString(value)
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			res, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return err
			}
			v.Field(i).SetUint(res)
		case reflect.Float32:
			res, err := strconv.ParseFloat(value, 32)
			if err != nil {
				return err
			}
			v.Field(i).SetFloat(res)
		case reflect.Float64:
			res, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return err
			}
			v.Field(i).SetFloat(res)
		case reflect.Slice:
			var strArray []string
			var valArray []reflect.Value
			var valArr reflect.Value
			elemKind := t.Field(i).Type.Elem().Kind()
			elemType := t.Field(i).Type.Elem()
			value = strings.Trim(strings.Trim(value, "["), "]")
			strArray = strings.Split(value, ",")
			switch elemKind {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				for _, e := range strArray {
					ee, err := strconv.ParseInt(e, 10, 64)
					if err != nil {
						return err
					}
					valArray = append(valArray, reflect.ValueOf(ee).Convert(elemType))
				}
			case reflect.String:
				for _, e := range strArray {
					valArray = append(valArray, reflect.ValueOf(strings.Trim(e, "\"")).Convert(elemType))
				}
			}
			valArr = reflect.Append(v.Field(i), valArray...)
			v.Field(i).Set(valArr)
		}
	}
	return nil
}
