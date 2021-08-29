package main

import (
	"fmt"
	"hids-agent/collector"
	"hids-agent/network"
	"reflect"
	"strings"

	"github.com/fatih/color"
	"github.com/modood/table"
)

// 测试阶段
func init() {
	if sockets, err := collector.GetSockets(true, network.TCP_ESTABLISHED); err != nil {
		fmt.Println(err)
	} else {
		table.Output(sockets)
	}
	collector.CN_PROC_START()
}

func main() {
	collector.Singleton.FlushProcessCache()
	for log := range network.KafkaChannel {
		fmt.Println(color.HiGreenString("[+]"), log.Process.PID)
		PrintVar(log, 1)
	}
}

func PrintStruct(t reflect.Type, v reflect.Value, pc int) {
	for i := 0; i < t.NumField(); i++ {
		fmt.Print(strings.Repeat("\t", pc), t.Field(i).Name, ":")
		value := v.Field(i)
		PrintVar(value.Interface(), pc+2)
		fmt.Println("")
	}
}

func PrintArraySlice(v reflect.Value, pc int) {
	for j := 0; j < v.Len(); j++ {
		PrintVar(v.Index(j).Interface(), pc+2)
	}
}
func PrintMap(v reflect.Value, pc int) {
	for _, k := range v.MapKeys() {
		PrintVar(k.Interface(), pc)
		PrintVar(v.MapIndex(k).Interface(), pc)
	}
}

func PrintVar(i interface{}, ident int) {
	t := reflect.TypeOf(i)
	v := reflect.ValueOf(i)
	if v.Kind() == reflect.Ptr {

		v = reflect.ValueOf(i).Elem()
		t = v.Type()
	}
	switch v.Kind() {
	case reflect.Array:
		PrintArraySlice(v, ident)
	case reflect.Chan:
		fmt.Println("Chan")
	case reflect.Func:
		fmt.Println("Func")
	case reflect.Interface:
		fmt.Println("Interface")
	case reflect.Map:
		PrintMap(v, ident)
	case reflect.Slice:
		PrintArraySlice(v, ident)
	case reflect.Struct:
		PrintStruct(t, v, ident)
	case reflect.UnsafePointer:
		fmt.Println("UnsafePointer")
	default:
		fmt.Print(strings.Repeat(" ", ident), v.Interface())
	}
}
