package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/routing"
)

type googJSON struct {
	SyncToken    string              `json:"syncToken"`
	CreationTime string              `json:"creationTime"`
	Prefixes     []map[string]string `json:"prefixes"`
}

func loadPrefixes() (v4 []netip.Prefix, v6 []netip.Prefix, err error) {
	raw, err := os.ReadFile("goog.json")
	if err != nil {
		return
	}

	var data googJSON
	err = json.Unmarshal(raw, &data)
	if err != nil {
		return
	}

	v4, v6 = []netip.Prefix{}, []netip.Prefix{}
	for _, each := range data.Prefixes {
		prefixString, ok := each["ipv4Prefix"]
		if !ok {
			prefixString, _ = each["ipv6Prefix"]
		}
		var prefix netip.Prefix
		prefix, err = netip.ParsePrefix(prefixString)
		if err != nil {
			return
		}
		if ok {
			v4 = append(v4, prefix)
		} else {
			v6 = append(v6, prefix)
		}
	}
	return
}

func splitPrefixes(v4 []netip.Prefix, minLength int) []netip.Prefix {
	result := []netip.Prefix{}
	for _, prefix := range v4 {
		if prefix.Bits() >= minLength {
			result = append(result, prefix)
			continue
		}
		addr := prefix.Masked().Addr().As4()
		iaddr := uint32(addr[0]) << 24 | uint32(addr[1]) << 16 | uint32(addr[2]) << 8 | uint32(addr[3])
		subnetSize := uint32(1) << (32 - minLength)
		for i := 0; i < 1 << (minLength - prefix.Bits()); i++ {
			result = append(result, netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(iaddr >> 24), byte(iaddr >> 16), byte(iaddr >> 8), byte(iaddr)}), minLength))
			iaddr += subnetSize
		}
	}
	return result
}

func sendPacketAndRetry(handle *pcap.Handle, packet []byte, retry int) (err error) {
	for _ = range retry {
		err = handle.WritePacketData(packet)
		if err == nil {
			return
		}
	}
	return
}

func sendSYNPackets(iface *net.Interface, gateway netip.Addr, src netip.Addr, goroutineNum int) {
	t, err := newTCPSYNPacketTemplate(context.Background(), netip.MustParseAddr("8.8.8.8"), 443, iface, gateway, src)
	if err != nil {
		panic(err)
	}

	device, err := interfaceToDevice(iface)
	if err != nil {
		panic(err)
	}

	v4, _, err := loadPrefixes()
	if err != nil {
		panic(err)
	}

	totalNum := 0
	for _, each := range v4 {
		totalNum += 1 << (32 - each.Bits())
	}

	split := splitPrefixes(v4, 16)

	prefixBuffer := []netip.Prefix{}
	addrNum := 0

	wg := sync.WaitGroup{}
	for i, each := range split {
		prefixBuffer = append(prefixBuffer, each)
		addrNum += 1 << (32 - each.Bits())
		if addrNum * goroutineNum < totalNum && i != len(split) - 1 {
			continue
		}
		prefixes := make([]netip.Prefix, len(prefixBuffer))
		copy(prefixes, prefixBuffer)
		wg.Go(func() {
			handle, err := pcap.OpenLive(device.Name, 65535, false, pcap.BlockForever)
			if err != nil {
				panic(err)
			}
			defer handle.Close()

			for _, each := range prefixes {
				addr := each.Addr()
				for i := uint64(0); i < uint64(1) << (32 - each.Bits()); i++ {
					err := sendPacketAndRetry(handle, t.generatePacket(addr), 5)
					if err != nil {
						log.Println(fmt.Errorf("error when send to %v: %w", addr, err))
					}
					addr = addr.Next()
				}
				log.Println("finished send packet to", each)
			}
		})
		prefixBuffer = []netip.Prefix{}
		addrNum = 0
	}
	wg.Wait()
}

func listenSYNACKPackets(ctx context.Context, wg *sync.WaitGroup, iface *net.Interface, src netip.Addr) {
	defer wg.Done()

	v4, _, err := loadPrefixes()
	if err != nil {
		panic(err)
	}

	addrSet := make(map[netip.Addr]struct{})

	buffer := newIPBuffer("ip.txt", 256)

	device, err := interfaceToDevice(iface)
	if err != nil {
		panic(err)
	}

	handle, err := pcap.OpenLive(device.Name, 65535, false, 1 * time.Second)
	if err != nil {
		panic(err)
	}
	defer handle.Close();

	lastStats, err := handle.Stats()
	if err != nil {
		panic(err)
	}

	timer := time.NewTimer(3 * time.Second)

	handle.SetBPFFilter(fmt.Sprintf("ip dst host %v && tcp src port 443 && tcp dst port 12138 && tcp[8:4] == 0x6666CD00 && tcp[13] & 0x12 == 0x12", src))
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType()).PacketsCtx(ctx)
loop:
	for {
		select {
		case packet, ok := <- packetSource:
			if !ok {
				break loop
			}

			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				log.Println("received a packet without IPv4 Layer:", encode(packet.Data()))
				continue
			}

			ip := ipLayer.(*layers.IPv4)
			packetSrc, ok := netip.AddrFromSlice(ip.SrcIP)
			if !ok || !packetSrc.Is4() {
				log.Println("received a packet with invalid IPv4 Address:", encode(packet.Data()))
				continue
			}

			flag := false
			for _, prefix := range v4 {
				if prefix.Contains(packetSrc) {
					flag = true
					break
				}
			}
			if !flag {
				continue
			}

			_, ok = addrSet[packetSrc]
			if ok {
				continue
			}

			addrSet[packetSrc] = struct{}{}

			err = buffer.append(packetSrc)
			if err != nil {
				panic(err)
			}
		case <- timer.C:
			timer.Reset(3 * time.Second)
			stats, err := handle.Stats()
			if err == nil {
				if stats.PacketsDropped > lastStats.PacketsDropped {
					log.Println("dropped", stats.PacketsDropped - lastStats.PacketsDropped)
				}
				if stats.PacketsIfDropped > lastStats.PacketsIfDropped {
					log.Println("if dropped", stats.PacketsIfDropped - lastStats.PacketsIfDropped)
				}
			} else {
				log.Println(err)
			}
			lastStats = stats
		}
	}
	err = buffer.flush()
	if err != nil {
		panic(err)
	}
}

func main() {
	goroutineNum := flag.Int("n", 4, "maximum number of threads")
	flag.Parse()

	router, err := routing.New()
	if err != nil {
		panic(err)
	}

	iface, gateway, src, err := router.Route(net.ParseIP("8.8.8.8"))
	if err != nil {
		panic(err)
	}

	gatewayAddr, ok := netip.AddrFromSlice(gateway)
	if !ok {
		panic(ok)
	}

	srcAddr, ok := netip.AddrFromSlice(src)
	if !ok {
		panic(ok)
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go listenSYNACKPackets(ctx, &wg, iface, srcAddr)

	sendSYNPackets(iface, gatewayAddr, srcAddr, *goroutineNum)

	time.Sleep(3 * time.Second)
	cancel()
	wg.Wait()
}