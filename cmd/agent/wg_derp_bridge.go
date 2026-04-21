package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
)

// wgDERPBridge bridges WireGuard packets between the kernel WG interface (UDP)
// and the DERP relay (WebSocket). This allows CLI clients using WG-over-DERP
// to communicate with the agent's kernel WireGuard interface.
//
// Architecture:
//   CLI (wireguard-go + DERPBind) <--wg_packet via DERP--> Agent (kernel WG + bridge)
//
// The bridge opens a local UDP socket. For each CLI peer, kernel WG is configured
// with endpoint 127.0.0.1:<bridgePort>. The bridge shuttles packets:
//   DERP wg_packet → decode → UDP write to kernel WG listen port
//   kernel WG UDP reply → read from bridge socket → encode → DERP wg_packet
type wgDERPBridge struct {
	mu         sync.Mutex
	dm         *derpManager
	wgPort     int    // kernel WG listen port (e.g. 40003)
	bridgeConn *net.UDPConn
	bridgePort int
	// peerByAddr maps source UDP addr (kernel WG sends from wgPort) to DERP peer ID
	peerByAddr map[string]string
	// addrByPeer maps DERP peer ID to the addr we use when injecting their packets
	addrByPeer map[string]*net.UDPAddr
}

func newWGDERPBridge(dm *derpManager, wgListenPort int) (*wgDERPBridge, error) {
	// Listen on a random local UDP port
	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("wg-derp bridge listen: %w", err)
	}

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	b := &wgDERPBridge{
		dm:         dm,
		wgPort:     wgListenPort,
		bridgeConn: conn,
		bridgePort: localAddr.Port,
		peerByAddr: make(map[string]string),
		addrByPeer: make(map[string]*net.UDPAddr),
	}

	// Start reading replies from kernel WG
	go b.readLoop()

	return b, nil
}

// BridgePort returns the local UDP port. CLI peers should have their
// kernel WG endpoint set to 127.0.0.1:<BridgePort>.
func (b *wgDERPBridge) BridgePort() int {
	return b.bridgePort
}

// DeliverFromDERP handles an incoming wg_packet from the DERP relay.
// It decodes the packet and sends it via UDP to the kernel WG listen port.
func (b *wgDERPBridge) DeliverFromDERP(fromPeerID string, packet []byte) {
	wgAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: b.wgPort}

	log.Printf("wg-derp bridge: DeliverFromDERP peer=%s size=%d -> 127.0.0.1:%d", fromPeerID, len(packet), b.wgPort)

	// Send the raw WG packet to the kernel WG interface via UDP.
	_, err := b.bridgeConn.WriteToUDP(packet, wgAddr)
	if err != nil {
		log.Printf("wg-derp bridge: write to kernel WG: %v", err)
		return
	}

	// Remember which peer this address maps to so we can route replies
	b.mu.Lock()
	b.peerByAddr[wgAddr.String()] = fromPeerID
	b.addrByPeer[fromPeerID] = wgAddr
	b.mu.Unlock()
}

// readLoop reads UDP packets that kernel WG sends back (replies to our injected packets).
// These are encrypted WG response packets destined for the CLI peer.
func (b *wgDERPBridge) readLoop() {
	buf := make([]byte, 65536)
	log.Printf("wg-derp bridge: readLoop started, listening on port %d", b.bridgePort)
	for {
		n, remoteAddr, err := b.bridgeConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("wg-derp bridge: readLoop error: %v", err)
			return
		}
		if n == 0 {
			continue
		}

		log.Printf("wg-derp bridge: readLoop got %d bytes from %s", n, remoteAddr)

		// Find the target peer — broadcast to all known DERP peers.
		b.mu.Lock()
		peers := make([]string, 0, len(b.peerByAddr))
		seen := make(map[string]bool)
		for _, peerID := range b.peerByAddr {
			if !seen[peerID] {
				peers = append(peers, peerID)
				seen[peerID] = true
			}
		}
		b.mu.Unlock()

		if len(peers) == 0 {
			log.Printf("wg-derp bridge: readLoop no known peers to forward to")
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		for _, peerID := range peers {
			log.Printf("wg-derp bridge: forwarding %d bytes to DERP peer %s", n, peerID)
			b.sendWGPacketToDERP(peerID, packet)
		}
	}
}

func (b *wgDERPBridge) sendWGPacketToDERP(toPeerID string, packet []byte) {
	payload, _ := json.Marshal(map[string]string{
		"packet": base64.StdEncoding.EncodeToString(packet),
	})

	msg := derpMessage{
		Type: "wg_packet",
		From: b.dm.clientID,
		To:   toPeerID,
		Data: json.RawMessage(payload),
	}

	b.dm.connMu.RLock()
	conn := b.dm.conn
	b.dm.connMu.RUnlock()

	if conn == nil {
		return
	}
	if err := b.dm.writeMessage(conn, msg); err != nil {
		log.Printf("wg-derp bridge: send wg_packet to %s: %v", toPeerID, err)
	}
}

func (b *wgDERPBridge) Close() {
	if b.bridgeConn != nil {
		b.bridgeConn.Close()
	}
}
