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
	require(os.WriteFile("sdk-typed-go.txt", []byte("typed\nsecond\nthird"), 0600) == nil)
	path = C.CString("sdk-typed-go.txt")
	var input, typed, typedLine, typedPath *C.SnAbiValue
	require(C.sn_abi_v1_string_copy(path, &input) == C.SN_ABI_OK)
	C.free(unsafe.Pointer(path))
	require(C.sn_sdk_text_file_open_abi(input, &typed) == C.SN_ABI_OK)
	C.sn_abi_v1_release(input)
	typedAlias := C.sn_abi_v1_retain(typed)
	C.sn_abi_v1_release(typed)
	runtime.GC()
	var opened C.int32_t
	require(C.sn_sdk_text_file_is_open_abi(typedAlias, &opened) == C.SN_ABI_OK && opened == 1)
	require(C.sn_sdk_text_file_read_line_abi(typedAlias, &typedLine) == C.SN_ABI_OK)
	require(C.sn_abi_v1_bytes(typedLine, &bytes) == C.SN_ABI_OK)
	require(string(C.GoBytes(unsafe.Pointer(bytes.data), C.int(bytes.length))) == "typed")
	var lines, ownedLine *C.SnAbiValue
	require(C.sn_sdk_text_file_read_lines_abi(typedAlias, &lines) == C.SN_ABI_OK)
	require(C.sn_abi_v1_value_array_get(lines, 0, &ownedLine) == C.SN_ABI_OK)
	C.sn_abi_v1_release(lines)
	require(C.sn_sdk_text_file_path_abi(typedAlias, &typedPath) == C.SN_ABI_OK)
	require(C.sn_sdk_text_file_dispose_abi(typedAlias) == C.SN_ABI_OK)
	require(C.sn_sdk_text_file_dispose_abi(typedAlias) == C.SN_ABI_OK)
	require(C.sn_sdk_text_file_is_open_abi(typedAlias, &opened) == C.SN_ABI_OK && opened == 0)
	C.sn_abi_v1_release(typedAlias)
	runtime.GC()
	require(C.sn_abi_v1_bytes(typedPath, &bytes) == C.SN_ABI_OK)
	require(string(C.GoBytes(unsafe.Pointer(bytes.data), C.int(bytes.length))) == "sdk-typed-go.txt")
	require(C.sn_abi_v1_bytes(ownedLine, &bytes) == C.SN_ABI_OK)
	require(string(C.GoBytes(unsafe.Pointer(bytes.data), C.int(bytes.length))) == "second")
	C.sn_abi_v1_release(ownedLine)
	C.sn_abi_v1_release(typedPath)
	C.sn_abi_v1_release(typedLine)
	require(os.Remove("sdk-typed-go.txt") == nil)
	fmt.Println("SDK native TextFile: pass")
}
