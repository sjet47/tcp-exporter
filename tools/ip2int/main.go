package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
)

func main() {
	ip := net.ParseIP(os.Args[1])
	fmt.Println(binary.LittleEndian.Uint32(ip.To4()))
}
