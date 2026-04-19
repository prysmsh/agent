package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

const nethelperSocket = "/var/run/prysm/nethelper.sock"

type nethelperClient struct {
	socketPath string
	nextID     atomic.Int64
}

type nhRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
	ID      int64  `json:"id"`
}

type nhResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *nhError        `json:"error,omitempty"`
	ID      int64           `json:"id"`
}

type nhError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func newNethelperClient() *nethelperClient {
	return &nethelperClient{socketPath: nethelperSocket}
}

func (c *nethelperClient) available() bool {
	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (c *nethelperClient) call(method string, params any) (json.RawMessage, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to nethelper: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	req := nhRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      c.nextID.Add(1),
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	data = append(data, '\n')

	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}
		return nil, fmt.Errorf("no response from nethelper")
	}

	var resp nhResponse
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("nethelper %s: [%d] %s", method, resp.Error.Code, resp.Error.Message)
	}

	return resp.Result, nil
}

func (c *nethelperClient) ifaceCreate(listenPort int, privateKeyPath string) error {
	_, err := c.call("iface.create", map[string]any{
		"listen_port":      listenPort,
		"private_key_path": privateKeyPath,
	})
	return err
}

func (c *nethelperClient) ifaceDelete() error {
	_, err := c.call("iface.delete", nil)
	return err
}

func (c *nethelperClient) ifaceAddAddr(cidr string) error {
	_, err := c.call("iface.addAddr", map[string]string{
		"cidr": cidr,
	})
	return err
}

func (c *nethelperClient) ifaceSetUp() error {
	_, err := c.call("iface.setUp", nil)
	return err
}

func (c *nethelperClient) peerSet(publicKey, endpoint string, allowedIPs []string) error {
	_, err := c.call("peer.set", map[string]any{
		"public_key":  publicKey,
		"endpoint":    endpoint,
		"allowed_ips": allowedIPs,
	})
	return err
}
