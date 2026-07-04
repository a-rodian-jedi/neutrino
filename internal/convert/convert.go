package convert

import (
	"bytes"
	"unsafe"
)

// int8SliceToString converts a null-terminated int8 array (from C char[])
// to a Go string. bpf2go generates int8 fields for C char arrays.
func Int8SliceToString(s []int8) string {
	// Convert []int8 to []byte without allocation using unsafe
	b := unsafe.Slice((*byte)(unsafe.Pointer(&s[0])), len(s))
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(b[:n])
}
