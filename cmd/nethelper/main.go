package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	socketPath = "/var/run/prysm/nethelper.sock"
	ifaceName  = "prysm0"
	keyBaseDir = "/var/lib/prysm-agent/"
	prysmGID   = 1001
)

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      any             `json:"id"`
}

type jsonRPCResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
	ID      any       `json:"id"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type ifaceCreateParams struct {
	ListenPort     int    `json:"listen_port"`
	PrivateKeyPath string `json:"private_key_path"`
}

type ifaceAddAddrParams struct {
	CIDR string `json:"cidr"`
}

type routeReplaceParams struct {
	CIDR string `json:"cidr"`
	Dev  string `json:"dev"`
}

type peerSetParams struct {
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowed_ips"`
}

func main() {
	log.SetPrefix("nethelper: ")
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	if os.Geteuid() != 0 {
		log.Fatal("must run as root")
	}

	if err := os.MkdirAll(filepath.Dir(socketPath), 0750); err != nil {
		log.Fatalf("create socket dir: %v", err)
	}

	os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("listen %s: %v", socketPath, err)
	}

	if err := os.Chmod(socketPath, 0660); err != nil {
		log.Fatalf("chmod socket: %v", err)
	}
	if err := os.Chown(socketPath, 0, prysmGID); err != nil {
		log.Fatalf("chown socket: %v", err)
	}

	log.Printf("listening on %s", socketPath)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-sig
		log.Printf("shutting down")
		ln.Close()
		os.Remove(socketPath)
		os.Exit(0)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed") {
				return
			}
			log.Printf("accept: %v", err)
			continue
		}
		handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)

	for scanner.Scan() {
		var req jsonRPCRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			writeResponse(conn, jsonRPCResponse{
				JSONRPC: "2.0",
				Error:   &rpcError{Code: -32700, Message: "parse error"},
				ID:      nil,
			})
			continue
		}

		if req.JSONRPC != "2.0" {
			writeResponse(conn, jsonRPCResponse{
				JSONRPC: "2.0",
				Error:   &rpcError{Code: -32600, Message: "invalid jsonrpc version"},
				ID:      req.ID,
			})
			continue
		}

		resp := dispatch(req)
		writeResponse(conn, resp)
	}
}

func writeResponse(conn net.Conn, resp jsonRPCResponse) {
	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	conn.Write(data)
}

func dispatch(req jsonRPCRequest) jsonRPCResponse {
	ok := func(result any) jsonRPCResponse {
		return jsonRPCResponse{JSONRPC: "2.0", Result: result, ID: req.ID}
	}
	fail := func(code int, msg string) jsonRPCResponse {
		return jsonRPCResponse{JSONRPC: "2.0", Error: &rpcError{Code: code, Message: msg}, ID: req.ID}
	}

	switch req.Method {
	case "iface.create":
		var p ifaceCreateParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return fail(-32602, "invalid params: "+err.Error())
		}
		if err := validateKeyPath(p.PrivateKeyPath); err != nil {
			return fail(-32602, err.Error())
		}
		if p.ListenPort < 1 || p.ListenPort > 65535 {
			return fail(-32602, "listen_port must be 1-65535")
		}
		log.Printf("iface.create listen_port=%d key=%s", p.ListenPort, p.PrivateKeyPath)

		// Clean up any stale interface
		_ = runCmd("ip", "link", "del", ifaceName)

		if err := runCmd("ip", "link", "add", ifaceName, "type", "wireguard"); err != nil {
			return fail(-32000, "ip link add: "+err.Error())
		}
		if err := runCmd("wg", "set", ifaceName,
			"private-key", p.PrivateKeyPath,
			"listen-port", fmt.Sprintf("%d", p.ListenPort),
		); err != nil {
			_ = runCmd("ip", "link", "del", ifaceName)
			return fail(-32000, "wg set: "+err.Error())
		}
		return ok("created")

	case "iface.delete":
		log.Printf("iface.delete")
		if err := runCmd("ip", "link", "del", ifaceName); err != nil {
			return fail(-32000, "ip link del: "+err.Error())
		}
		return ok("deleted")

	case "iface.addAddr":
		var p ifaceAddAddrParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return fail(-32602, "invalid params: "+err.Error())
		}
		if err := validateCIDR(p.CIDR); err != nil {
			return fail(-32602, err.Error())
		}
		log.Printf("iface.addAddr cidr=%s", p.CIDR)
		if err := runCmd("ip", "addr", "add", p.CIDR, "dev", ifaceName); err != nil {
			return fail(-32000, "ip addr add: "+err.Error())
		}
		return ok("added")

	case "iface.setUp":
		log.Printf("iface.setUp")
		if err := runCmd("ip", "link", "set", ifaceName, "up"); err != nil {
			return fail(-32000, "ip link set up: "+err.Error())
		}
		return ok("up")

	case "peer.set":
		var p peerSetParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return fail(-32602, "invalid params: "+err.Error())
		}
		if err := validateBase64Key(p.PublicKey); err != nil {
			return fail(-32602, "invalid public_key: "+err.Error())
		}
		for _, cidr := range p.AllowedIPs {
			if err := validateCIDR(cidr); err != nil {
				return fail(-32602, "invalid allowed_ip: "+err.Error())
			}
		}
		pubPrefix := p.PublicKey
		if len(pubPrefix) > 16 {
			pubPrefix = pubPrefix[:16]
		}
		log.Printf("peer.set pubkey=%s endpoint=%s allowed=%s",
			pubPrefix, p.Endpoint, strings.Join(p.AllowedIPs, ","))

		args := []string{"set", ifaceName, "peer", p.PublicKey,
			"allowed-ips", strings.Join(p.AllowedIPs, ","),
		}
		if p.Endpoint != "" {
			args = append(args, "endpoint", p.Endpoint)
		}
		if err := runCmd("wg", args...); err != nil {
			return fail(-32000, "wg set peer: "+err.Error())
		}
		return ok("set")

	case "route.replace":
		var p routeReplaceParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return fail(-32602, "invalid params: "+err.Error())
		}
		if err := validateCIDR(p.CIDR); err != nil {
			return fail(-32602, err.Error())
		}
		dev := p.Dev
		if dev == "" {
			dev = ifaceName
		}
		log.Printf("route.replace cidr=%s dev=%s", p.CIDR, dev)
		if err := runCmd("ip", "route", "replace", p.CIDR, "dev", dev); err != nil {
			return fail(-32000, "ip route replace: "+err.Error())
		}
		return ok("replaced")

	case "iptables.ensureAccept":
		// Ensure an ACCEPT rule exists in ts-input for the WG interface.
		// This is needed because Tailscale drops 100.64.0.0/10 traffic
		// from non-tailscale0 interfaces.
		log.Printf("iptables.ensureAccept iface=%s", ifaceName)
		// Check if rule already exists.
		if err := runCmd("iptables", "-C", "ts-input", "-i", ifaceName, "-j", "ACCEPT"); err == nil {
			return ok("exists")
		}
		// Insert before the DROP rule (position 3 in ts-input).
		if err := runCmd("iptables", "-I", "ts-input", "3", "-i", ifaceName, "-j", "ACCEPT"); err != nil {
			// ts-input chain might not exist (no Tailscale). Non-fatal.
			log.Printf("iptables.ensureAccept: %v (non-fatal)", err)
			return ok("skipped")
		}
		return ok("added")

	default:
		return fail(-32601, "method not found: "+req.Method)
	}
}

func validateKeyPath(path string) error {
	cleaned := filepath.Clean(path)
	if !strings.HasPrefix(cleaned, keyBaseDir) {
		return fmt.Errorf("key path must be under %s", keyBaseDir)
	}
	return nil
}

func validateCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %v", cidr, err)
	}
	return nil
}

func validateBase64Key(key string) error {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("not valid base64: %v", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("decoded key must be 32 bytes, got %d", len(b))
	}
	return nil
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
