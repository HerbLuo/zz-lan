package main

import (
	"log"
	"net"
)

func getInterfaceConfig(interfaceName string) {
	var ifs []net.Interface
	var err error
	if interfaceName == "" {
		ifs, err = net.Interfaces()
	} else {
		// 已经选择interfaceName
		var it *net.Interface
		it, err = net.InterfaceByName(interfaceName)
		if err == nil {
			ifs = append(ifs, *it)
		}
	}
	if err != nil {
		log.Fatal("无法获取本地网络信息:", err)
	}
	log.Println(ifs)
	for _, it := range ifs {
		addr, _ := it.Addrs()
		for _, a := range addr {
			if ip, ok := a.(*net.IPNet); ok && !ip.IP.IsLoopback() {
				if ip.IP.To4() != nil {
					ipNet = ip
					localHaddr = it.HardwareAddr
					iface = it.Name
					goto END
				}
			}
		}
	}

END:
	if ipNet == nil || len(localHaddr) == 0 {
		log.Fatal("无法获取本地网络信息")
	}
}
