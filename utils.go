package main

import (
	"encoding/base64"
	"fmt"
	"net"

	"github.com/gopacket/gopacket/pcap"
)

func encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func interfaceToDevice(iface *net.Interface) (*pcap.Interface, error) {
	interfaceAddrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	devices, _ := pcap.FindAllDevs()
	for _, interfaceAddr := range interfaceAddrs {
		inet, ok := interfaceAddr.(*net.IPNet)
		if !ok {
			continue
		}
		for _, device := range devices {
			for _, deviceAddr := range device.Addresses {
				if deviceAddr.IP.Equal(inet.IP) {
					return &device, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("device related to %v not found", iface.Name)
}

func deviceToInterface(device *pcap.Interface) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, deviceAddr := range device.Addresses {
		for _, iface := range interfaces {
			interfaceAddrs, err := iface.Addrs()
			if err != nil {
				return nil, err
			}
			for _, interfaceAddr := range interfaceAddrs {
				inet, ok := interfaceAddr.(*net.IPNet)
				if !ok {
					continue
				}
				if inet.IP.Equal(deviceAddr.IP) {
					return &iface, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("interface related to %v not found", device.Name)
}