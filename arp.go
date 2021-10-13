package main

import (
	"context"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
)

type ARP struct {
	networkInterface string
	context context.Context
	onPacket func(ip net.IP, mac net.HardwareAddr)

	sourceIp net.IP
	sourceMac net.HardwareAddr
}

func (arp *ARP) listen() {
	handle, err := pcap.OpenLive(arp.networkInterface, 1024, false, arpListenTimeout)
	if err != nil {
		log.Fatal("pcap打开失败:", err)
	}

	defer handle.Close()
	err = handle.SetBPFFilter("arp")
	if err != nil {
		log.Fatal("设置arp过滤失败", err)
	}

	ps := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <- arp.context.Done():
			return
		case p := <- ps.Packets():
			layer := p.Layer(layers.LayerTypeARP).(*layers.ARP)
			if layer.Operation == 2 {
				mac := net.HardwareAddr(layer.SourceHwAddress)
				arp.onPacket(layer.SourceProtAddress, mac)

				//m := manuf.Search(mac.String())
				//pushData(ParseIP(layer.SourceProtAddress).String(), mac, "", m)
				//if strings.Contains(m, "Apple") {
				//	go sendMdns(ParseIP(layer.SourceProtAddress), mac)
				//} else {
				//	go sendNbns(ParseIP(layer.SourceProtAddress), mac)
				//}
			}
		}
	}
}

func (arp *ARP) send(targetIp net.IP) {
	//srcIp := net.ParseIP(ipNet.IP.String()).To4()
	//dstIp := net.ParseIP(ip.String()).To4()
	//if srcIp == nil || dstIp == nil {
	//	log.Fatal("ip 解析出问题")
	//}
	// 以太网首部
	// EthernetType 0x0806  ARP
	ether := &layers.Ethernet{
		SrcMAC:       arp.sourceMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	a := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(6),
		ProtAddressSize:   uint8(4),
		Operation:         uint16(1), // 0x0001 arp request 0x0002 arp response
		SourceHwAddress:   arp.sourceMac,
		SourceProtAddress: arp.sourceIp,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    targetIp,
	}

	buffer := gopacket.NewSerializeBuffer()
	var opt gopacket.SerializeOptions
	_ = gopacket.SerializeLayers(buffer, opt, ether, a)
	outgoingPacket := buffer.Bytes()

	handle, err := pcap.OpenLive(arp.networkInterface, 2048, false, arpSendTimeout)
	if err != nil {
		log.Fatal("pcap打开失败:", err)
	}
	defer handle.Close()

	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal("发送arp数据包失败..")
	}
}
