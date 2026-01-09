package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type arpHelper struct {
	handle       *pcap.Handle
	addr         netip.Addr
	hardwareAddr net.HardwareAddr

	cancel context.CancelFunc

	requestChannel   chan struct {addr netip.Addr; channel chan<- net.HardwareAddr}
	cancelChannel    chan netip.Addr
	responseChannels map[netip.Addr][]chan<- net.HardwareAddr
}

func newARPHelper(iface *net.Interface) (*arpHelper, error) {
	ah := &arpHelper{
		requestChannel: make(chan struct{addr netip.Addr; channel chan<- net.HardwareAddr}),
		cancelChannel: make(chan netip.Addr),
		responseChannels: make(map[netip.Addr][]chan<- net.HardwareAddr),
	}

	device, err := interfaceToDevice(iface)
	if err != nil {
		return nil, err
	}
	for _, deviceAddr := range device.Addresses {
		addr, ok := netip.AddrFromSlice(deviceAddr.IP)
		if !ok || !addr.Is4() {
			continue
		}
		ah.addr = addr
	}
	if ah.addr.IsUnspecified() {
		return nil, fmt.Errorf("IPv4 address of %v not found", iface.Name)
	}

	ah.hardwareAddr = iface.HardwareAddr

	ah.handle, err = pcap.OpenLive(device.Name, 65535, false, 1 * time.Second)
	if err != nil {
		return nil, err
	}

	err = ah.handle.SetBPFFilter(fmt.Sprintf("arp[0:4] == 0x00010800 && arp[4:4] == 0x06040002 && arp[8:4] == ether[6:4] && arp[12:2] == ether[10:2] && arp[18:4] == ether[0:4] && arp[22:2] == ether[4:2] && arp dst %v", ah.addr.String()))
	if err != nil {
		ah.handle.Close()
		return nil, err
	}
	return ah, nil
}

func (ah *arpHelper) close() {
	if ah.cancel != nil {
		ah.cancel()
	}
	ah.handle.Close()
	close(ah.requestChannel)
	close(ah.cancelChannel)
	for _, channels := range ah.responseChannels {
		for _, each := range channels {
			close(each)
		}
	}
	for addr := range ah.responseChannels {
		delete(ah.responseChannels, addr)
	}
}

func (ah *arpHelper) serve(ctx context.Context) {
	var ownCtx context.Context
	ownCtx, ah.cancel = context.WithCancel(ctx)
	packetSource := gopacket.NewPacketSource(ah.handle, ah.handle.LinkType()).PacketsCtx(ownCtx)
loop:
	for {
		select {
		case packet, ok := <- packetSource:
			if !ok {
				ah.cancel = nil
				break loop
			}

			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				log.Println("received a packet without ARP Layer:", encode(packet.Data()))
				continue
			}

			arp := arpLayer.(*layers.ARP)
			src, ok := netip.AddrFromSlice(arp.SourceProtAddress)
			if !ok || !src.Is4() {
				log.Println("received a packet with invalid IPv4 Address:", encode(packet.Data()))
				continue
			}

			channels, ok := ah.responseChannels[src]
			if !ok {
				continue
			}

			srcHardware := arp.SourceHwAddress
			for _, each := range channels {
				each <- srcHardware
				close(each)
			}
			delete(ah.responseChannels, src)
		case addrWithChannel := <- ah.requestChannel:
			channels, ok := ah.responseChannels[addrWithChannel.addr]
			if ok {
				ah.responseChannels[addrWithChannel.addr] = append(channels, addrWithChannel.channel)
			} else {
				ah.responseChannels[addrWithChannel.addr] = []chan<- net.HardwareAddr{addrWithChannel.channel}
			}
		case addr := <- ah.cancelChannel:
			channels, ok := ah.responseChannels[addr]
			if !ok {
				continue
			}
			for _, each := range channels {
				close(each)
			}
			delete(ah.responseChannels, addr)
		}
	}
}

func (ah *arpHelper) getHardwareAddress(ctx context.Context, addr netip.Addr) net.HardwareAddr {
	channel := make(chan net.HardwareAddr)
	ah.requestChannel <- struct{addr netip.Addr; channel chan<- net.HardwareAddr}{addr: addr, channel: channel}

	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths: true,
	}, &layers.Ethernet{
		SrcMAC:       ah.hardwareAddr,
		DstMAC:       []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}, &layers.ARP{
		AddrType: layers.LinkTypeEthernet,
		Protocol: layers.EthernetTypeIPv4,
		Operation: layers.ARPRequest,
		SourceHwAddress: ah.hardwareAddr,
		SourceProtAddress: ah.addr.AsSlice(),
		DstHwAddress: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress: addr.AsSlice(),
	})
	ah.handle.WritePacketData(buffer.Bytes())
	select {
	case hardwareAddr, ok := <- channel:
		if !ok {
			return nil
		}
		return hardwareAddr
	case <- ctx.Done():
		ah.cancelChannel <- addr
		return nil
	}
}

func getHardwareAddress(ctx context.Context, iface *net.Interface, addr netip.Addr) (hardwareAddr net.HardwareAddr, err error) {
	ah, err := newARPHelper(iface)
	if err != nil {
		return
	}
	defer ah.close()
	go ah.serve(context.Background())
	hardwareAddr = ah.getHardwareAddress(ctx, addr)
	if hardwareAddr == nil {
		err = fmt.Errorf("canceled")
	}
	return
}