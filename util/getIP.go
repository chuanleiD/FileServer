package util

import (
	"fmt"
	"net"
)

func GetWLANIPv4() (string, error) {
	ifAceName := "WLAN"
	ifAce, err := net.InterfaceByName(ifAceName)
	if err != nil {
		return "", fmt.Errorf("interface %s not found", ifAceName)
	}

	addrs, err := ifAce.Addrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("no IPv4 address found for interface %s", ifAceName)
}
