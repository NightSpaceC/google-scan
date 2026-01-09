package main

import (
	"context"
	"net"
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type tcpSYNPacketTemplate struct {
	ethernet layers.Ethernet
	ip       layers.IPv4
	tcp      layers.TCP
}

func newTCPSYNPacketTemplate(ctx context.Context, example netip.Addr, dstPort uint16, iface *net.Interface, gateway netip.Addr, src netip.Addr) (t *tcpSYNPacketTemplate, err error) {
	dstHardwareAddr, err := getHardwareAddress(ctx, iface, gateway)
	if err != nil {
		return
	}

	t = &tcpSYNPacketTemplate{
		ethernet: layers.Ethernet{
			SrcMAC:       iface.HardwareAddr,
			DstMAC:       dstHardwareAddr,
			EthernetType: layers.EthernetTypeIPv4,
		},
		ip: layers.IPv4{
			Version: 4,
			IHL: 5,
			Id: 0x66CF,
			Flags: layers.IPv4DontFragment,
			TTL: 128,
			Protocol: layers.IPProtocolTCP,
			SrcIP: src.AsSlice(),
			DstIP: example.AsSlice(),
		},
		tcp: layers.TCP{
			SrcPort: layers.TCPPort(12138),
			DstPort: layers.TCPPort(dstPort),
			Seq: 0x6666CCFF,
			Ack: 0,
			SYN: true,
			Window: 65535,
		},
	}
	return t, nil
}

func (t *tcpSYNPacketTemplate) generatePacket(dst netip.Addr) []byte {
	ip := t.ip
	ip.DstIP = dst.AsSlice()
	tcp := t.tcp
	tcp.SetNetworkLayerForChecksum(&ip)
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths: true,
		ComputeChecksums: true,
	}, &t.ethernet, &ip, &tcp)
	if err != nil {
		panic(err)
	}
	return buffer.Bytes()
}