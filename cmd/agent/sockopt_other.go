//go:build !linux

// Package main provides stub implementations for SO_ORIGINAL_DST on non-Linux platforms.
// The tunnel daemon requires Linux for iptables REDIRECT interception.

package main

import (
	"fmt"
	"net"
)

// getOriginalDst is not supported on non-Linux platforms
func getOriginalDst(conn *net.TCPConn) (net.IP, int, error) {
	return nil, 0, fmt.Errorf("SO_ORIGINAL_DST not supported on this platform")
}

// isLocalIP checks if the given IP address is a local address on this machine
func isLocalIP(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}

	for _, addr := range addrs {
		var localIP net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			localIP = v.IP
		case *net.IPAddr:
			localIP = v.IP
		}

		if localIP != nil && localIP.Equal(ip) {
			return true
		}
	}

	return false
}
