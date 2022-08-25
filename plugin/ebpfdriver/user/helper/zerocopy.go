package helper

import (
	"reflect"
	"unsafe"
)

// related issue: https://github.com/golang/go/issues/25484
// found in: https://github.com/alibaba/ilogtail/blob/main/helper/string_helper.go
// new a string header, to point to the Data and Len field on original b []byte
// which is zero copy and way faster than the normal way.

//nolint:gosec
func ZeroCopyString(b []byte) (s string) {
	pbytes := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	pstring := (*reflect.StringHeader)(unsafe.Pointer(&s))
	pstring.Data = pbytes.Data
	pstring.Len = pbytes.Len
	return
}
