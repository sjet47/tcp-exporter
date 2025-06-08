package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
)

func main() {
	i32, err := strconv.ParseInt(os.Args[1], 10, 32)
	if err != nil {
		log.Panic(err)
	}

	addr := make(net.IP, 4)
	binary.LittleEndian.PutUint32(addr, uint32(i32))
	fmt.Println(addr.String())
}
