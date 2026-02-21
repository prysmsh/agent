//go:build linux

// Package main provides SO_ORIGINAL_DST support for retrieving the original destination
// address from connections that have been redirected by iptables REDIRECT target.
// This is used by the tunnel daemon to know where traffic was originally destined.

package main

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	// SO_ORIGINAL_DST is the socket option to get the original destination
	// from an iptables REDIRECT connection
	SO_ORIGINAL_DST = 80

	// IP6T_SO_ORIGINAL_DST is the IPv6 equivalent
	IP6T_SO_ORIGINAL_DST = 80
)

// sockaddrIn represents the IPv4 sockaddr structure
type sockaddrIn struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

// sockaddrIn6 represents the IPv6 sockaddr structure
type sockaddrIn6 struct {
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte
	ScopeID  uint32
}

// getOriginalDst retrieves the original destination address from a TCP connection
// that was redirected by iptables REDIRECT target. This uses the SO_ORIGINAL_DST
// socket option which is set by netfilter when the connection is redirected.
func getOriginalDst(conn *net.TCPConn) (net.IP, int, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get syscall conn: %w", err)
	}

	var ip net.IP
	var port int
	var sockErr error

	err = rawConn.Control(func(fd uintptr) {
		// Try IPv4 first
		var origAddr sockaddrIn
		size := uint32(unsafe.Sizeof(origAddr))

		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.SOL_IP,
			SO_ORIGINAL_DST,
			uintptr(unsafe.Pointer(&origAddr)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)

		if errno == 0 {
			// Success with IPv4
			ip = net.IPv4(origAddr.Addr[0], origAddr.Addr[1], origAddr.Addr[2], origAddr.Addr[3])
			// Port is in network byte order (big endian), need to convert
			port = int(origAddr.Port>>8) | int(origAddr.Port&0xff)<<8
			return
		}

		// Try IPv6
		var origAddr6 sockaddrIn6
		size6 := uint32(unsafe.Sizeof(origAddr6))

		_, _, errno = syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.SOL_IPV6,
			IP6T_SO_ORIGINAL_DST,
			uintptr(unsafe.Pointer(&origAddr6)),
			uintptr(unsafe.Pointer(&size6)),
			0,
		)

		if errno == 0 {
			// Success with IPv6
			ip = make(net.IP, 16)
			copy(ip, origAddr6.Addr[:])
			// Port is in network byte order (big endian), need to convert
			port = int(origAddr6.Port>>8) | int(origAddr6.Port&0xff)<<8
			return
		}

		sockErr = fmt.Errorf("getsockopt SO_ORIGINAL_DST failed: %v", errno)
	})

	if err != nil {
		return nil, 0, fmt.Errorf("control func failed: %w", err)
	}
	if sockErr != nil {
		return nil, 0, sockErr
	}

	return ip, port, nil
}

// IP_TRANSPARENT socket option for TPROXY support
const IP_TRANSPARENT = 19

// setTransparentSocketOptions sets IP_TRANSPARENT on a socket for TPROXY mode.
// This allows the socket to accept connections destined for any IP address,
// which is required for transparent proxying with iptables TPROXY.
// NOTE: This is kept for compatibility but NAT REDIRECT mode doesn't require it.
func setTransparentSocketOptions(network, address string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		// Set IP_TRANSPARENT to accept connections to any IP
		sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, IP_TRANSPARENT, 1)
		if sockErr != nil {
			return
		}
		// Also set SO_REUSEADDR for faster restarts
		sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return sockErr
}

// setReuseAddrSocketOption sets SO_REUSEADDR on a socket for faster restarts.
// Used by NAT REDIRECT mode which doesn't need IP_TRANSPARENT.
func setReuseAddrSocketOption(network, address string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return sockErr
}

// isLocalIP checks if the given IP address is a local address on this machine.
// This is used to detect when traffic is destined for the local node.
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
