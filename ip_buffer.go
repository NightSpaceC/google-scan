package main

import (
	"fmt"
	"net/netip"
	"os"
)

type ipBuffer struct {
	path       string
	buffer     []netip.Addr
	bufferSize int
	bufferCap  int
}

func newIPBuffer(path string, cap int) (*ipBuffer) {
	return &ipBuffer{
		path:       path,
		buffer:     make([]netip.Addr, cap),
		bufferSize: 0,
		bufferCap:  cap,
	}
}

func (b *ipBuffer) flush() error {
	file, err := os.OpenFile("ip.txt", os.O_WRONLY | os.O_APPEND | os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	for i := range b.bufferSize {
		_, err := fmt.Fprintln(file, b.buffer[i])
		if err != nil {
			return err
		}
	}
	b.bufferSize = 0
	return nil
}

func (b *ipBuffer) append(addr netip.Addr) error {
	b.buffer[b.bufferSize] = addr
	b.bufferSize++
	if b.bufferSize == b.bufferCap {
		return b.flush()
	}
	return nil
}