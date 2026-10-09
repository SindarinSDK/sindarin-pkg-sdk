package main

/*
#define SN_SDK_TEXTFILE_STANDALONE 1
#include <stdlib.h>
#include "textfile.native.h"
*/
import "C"
import (
	"fmt"
	"os"
	"runtime"
	"unsafe"
)

func require(ok bool) {
	if !ok {
		panic("SDK TextFile C ABI contract failed")
	}
}
func main() {
	path := C.CString("sdk-native-go-resource.txt")
	file := C.sn_text_file_open(path)
	C.free(unsafe.Pointer(path))
	require(file != nil && C.sn_sdk_text_file_is_open(file) == 1)
	alias := C.sn_sdk_text_file_retain(file)
	C.sn_sdk_text_file_release(file)
	runtime.GC()
	line := C.CString("alpha")
	C.sn_text_file_write_line(alias, line)
	C.free(unsafe.Pointer(line))
	var owned *C.SnAbiValue
	require(C.sn_sdk_text_file_path(alias, &owned) == C.SN_ABI_OK)
	C.sn_sdk_text_file_release(alias)
	runtime.GC()
	var bytes C.SnAbiBytes
	require(C.sn_abi_v1_bytes(owned, &bytes) == C.SN_ABI_OK)
	require(string(C.GoBytes(unsafe.Pointer(bytes.data), C.int(bytes.length))) == "sdk-native-go-resource.txt")
	C.sn_abi_v1_release(owned)
	data, err := os.ReadFile("sdk-native-go-resource.txt")
	require(err == nil && string(data) == "alpha\n")
	require(os.Remove("sdk-native-go-resource.txt") == nil)
	fmt.Println("SDK native TextFile: pass")
}
