//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	tunnelPodsDir = "/var/run/prysm/tunnel-pods"
)

// netnsListenerManager watches the tunnel-pods directory and starts a listener
// in each pod's network namespace. TPROXY redirects traffic to the listener
// in the same netns as the pod, so we must listen there.
type netnsListenerManager struct {
	t            *tunnelDaemon
	watcher      *fsnotify.Watcher
	mu           sync.Mutex
	activeListeners map[string]context.CancelFunc // podUID -> cancel
}

func newNetnsListenerManager(t *tunnelDaemon) *netnsListenerManager {
	return &netnsListenerManager{
		t:               t,
		activeListeners: make(map[string]context.CancelFunc),
	}
}

func (m *netnsListenerManager) Start(ctx context.Context) error {
	if err := os.MkdirAll(tunnelPodsDir, 0755); err != nil {
		return fmt.Errorf("create tunnel-pods dir: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create fsnotify watcher: %w", err)
	}
	m.watcher = watcher

	if err := watcher.Add(tunnelPodsDir); err != nil {
		watcher.Close()
		return fmt.Errorf("watch tunnel-pods dir: %w", err)
	}

	// Process existing pods on startup
	entries, err := os.ReadDir(tunnelPodsDir)
	if err != nil {
		watcher.Close()
		return fmt.Errorf("read tunnel-pods dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m.startListenerForPod(ctx, e.Name())
	}

	go m.watchLoop(ctx)
	log.Printf("tunnel: netns listener manager started (watching %s)", tunnelPodsDir)
	return nil
}

func (m *netnsListenerManager) watchLoop(ctx context.Context) {
	defer m.watcher.Close()
	for {
		select {
		case <-ctx.Done():
			m.stopAllListeners()
			return
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Write == fsnotify.Write {
				name := filepath.Base(event.Name)
				if name != "" && !strings.HasPrefix(name, ".") {
					m.startListenerForPod(ctx, name)
				}
			}
			if event.Op&fsnotify.Remove == fsnotify.Remove {
				name := filepath.Base(event.Name)
				m.stopListenerForPod(name)
			}
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("tunnel: fsnotify error: %v", err)
		}
	}
}

func (m *netnsListenerManager) startListenerForPod(ctx context.Context, podUID string) {
	m.mu.Lock()
	if _, exists := m.activeListeners[podUID]; exists {
		m.mu.Unlock()
		return
	}
	childCtx, cancel := context.WithCancel(ctx)
	m.activeListeners[podUID] = cancel
	m.mu.Unlock()

	go m.runListenerInNetns(childCtx, podUID)
}

func (m *netnsListenerManager) stopListenerForPod(podUID string) {
	m.mu.Lock()
	cancel, exists := m.activeListeners[podUID]
	if exists {
		delete(m.activeListeners, podUID)
		cancel()
	}
	m.mu.Unlock()
}

func (m *netnsListenerManager) stopAllListeners() {
	m.mu.Lock()
	for _, cancel := range m.activeListeners {
		cancel()
	}
	m.activeListeners = make(map[string]context.CancelFunc)
	m.mu.Unlock()
}

func (m *netnsListenerManager) runListenerInNetns(ctx context.Context, podUID string) {
	// Read the CNI-provided netns path (may not be accessible due to mount namespace isolation)
	netnsPathFile := filepath.Join(tunnelPodsDir, podUID)
	data, err := os.ReadFile(netnsPathFile)
	if err != nil {
		log.Printf("tunnel: failed to read netns path for %s: %v", podUID, err)
		return
	}
	cniNsPath := strings.TrimSpace(string(data))
	if cniNsPath == "" {
		return
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Try multiple approaches to open the pod's network namespace:
	// 1. First try to find the netns via /proc by searching for the pod UID in cgroups
	//    (this works when hostPID is enabled but mount propagation is not)
	// 2. Fall back to the original mount namespace approach
	//
	// IMPORTANT: Retry with backoff because there's a race condition - the CNI creates
	// the tunnel-pods file before the container processes start. We need to wait for
	// the pod's processes to appear in /proc.
	var nsHandle netns.NsHandle
	maxRetries := 5
	retryDelay := 500 * time.Millisecond
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(retryDelay):
				retryDelay *= 2 // exponential backoff
			}
		}

		nsHandle, err = findNetnsForPodUID(podUID)
		if err == nil {
			break // success
		}

		if attempt == maxRetries-1 {
			log.Printf("tunnel: findNetnsForPodUID failed for %s after %d attempts: %v, trying host mount ns", podUID, maxRetries, err)
			// Fall back to the original approach via host mount namespace
			nsHandle, err = openNetnsViaHostMountNs(cniNsPath)
			if err != nil {
				log.Printf("tunnel: failed to open netns for pod %s: %v", podUID, err)
				return
			}
		}
	}
	defer nsHandle.Close()

	origNs, err := netns.Get()
	if err != nil {
		log.Printf("tunnel: failed to get current netns: %v", err)
		return
	}
	defer origNs.Close()

	// Debug: check if the netns handle is valid
	log.Printf("tunnel: attempting netns.Set for pod %s (handle fd=%d, origNs fd=%d)", podUID, int(nsHandle), int(origNs))

	if err := netns.Set(nsHandle); err != nil {
		log.Printf("tunnel: failed to set netns for pod %s: %v (handle fd=%d)", podUID, err, int(nsHandle))
		return
	}
	defer netns.Set(origNs)

	// Use standard listener (no IP_TRANSPARENT needed for NAT REDIRECT mode)
	// Original destination is retrieved via SO_ORIGINAL_DST socket option
	lc := net.ListenConfig{
		Control: setReuseAddrSocketOption,
	}
	addr := fmt.Sprintf("0.0.0.0:%d", m.t.outboundPort)
	ln, err := lc.Listen(ctx, "tcp4", addr)
	if err != nil {
		log.Printf("tunnel: failed to listen in netns for pod %s: %v", podUID, err)
		return
	}
	defer ln.Close()

	log.Printf("tunnel: listening in netns for pod %s (port %d), entering accept loop", podUID, m.t.outboundPort)

	acceptCount := 0
	for {
		conn, err := ln.Accept()
		acceptCount++
		log.Printf("tunnel: Accept() returned for pod %s (count=%d, err=%v)", podUID, acceptCount, err)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("tunnel: accept error in pod %s netns: %v", podUID, err)
			continue
		}

		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			log.Printf("tunnel: accepted non-TCP connection in pod %s netns", podUID)
			conn.Close()
			continue
		}

		log.Printf("tunnel: accepted connection in pod %s netns: %s -> %s", podUID, conn.RemoteAddr(), conn.LocalAddr())

		select {
		case <-ctx.Done():
			conn.Close()
			return
		default:
			m.t.activeConns.Add(1)
			atomic.AddInt64(&m.t.stats.outboundConns, 1)
			go func() {
				defer m.t.activeConns.Done()
				m.t.handleOutboundInNetns(ctx, tcpConn, podUID)
			}()
		}
	}
}

// tunnelBypassMark is the socket mark used to bypass TPROXY rules.
// IMPORTANT: Must NOT have bit 0 set (0x1), as that's the TPROXY routing mark.
// The TPROXY ip rule matches fwmark 0x1/0x1 (any mark with bit 0 set).
// Using 0x800 (2048) which has bit 0 clear.
const tunnelBypassMark = 0x800

// dialInPodNetns dials a TCP connection from within the pod's network namespace.
// This is required because flannel routes are only accessible from the pod's netns.
// The socket is marked with tunnelBypassMark to bypass TPROXY rules and avoid loops.
func dialInPodNetns(podUID, network, address string, timeout time.Duration) (net.Conn, error) {
	// Channel to receive the result
	type dialResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan dialResult, 1)

	// Run the dial in a separate goroutine with locked OS thread
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		log.Printf("tunnel: dialInPodNetns starting for %s to %s", podUID, address)

		// Find the pod's network namespace
		nsHandle, err := findNetnsForPodUID(podUID)
		if err != nil {
			resultCh <- dialResult{nil, fmt.Errorf("find netns: %w", err)}
			return
		}
		defer nsHandle.Close()

		// Save original netns
		origNs, err := netns.Get()
		if err != nil {
			resultCh <- dialResult{nil, fmt.Errorf("get current netns: %w", err)}
			return
		}
		defer origNs.Close()

		// Switch to pod's netns
		if err := netns.Set(nsHandle); err != nil {
			resultCh <- dialResult{nil, fmt.Errorf("set netns: %w", err)}
			return
		}

		// Dial with SO_MARK to bypass TPROXY rules (avoid infinite loop)
		dialer := &net.Dialer{
			Timeout: timeout,
			Control: func(network, address string, c syscall.RawConn) error {
				var sockErr error
				if err := c.Control(func(fd uintptr) {
					sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, tunnelBypassMark)
					if sockErr != nil {
						log.Printf("tunnel: failed to set SO_MARK 0x%x on fd %d: %v", tunnelBypassMark, fd, sockErr)
					} else {
						// Verify the mark was set by reading it back
						mark, getErr := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
						if getErr != nil {
							log.Printf("tunnel: failed to verify SO_MARK: %v", getErr)
						} else if mark != tunnelBypassMark {
							log.Printf("tunnel: SO_MARK mismatch: set 0x%x but got 0x%x", tunnelBypassMark, mark)
						} else {
							log.Printf("tunnel: SO_MARK 0x%x verified on fd %d", mark, fd)
						}
					}
				}); err != nil {
					log.Printf("tunnel: Control callback error: %v", err)
					return err
				}
				return sockErr
			},
		}
		conn, err := dialer.Dial(network, address)

		// Switch back to original netns before returning
		if setErr := netns.Set(origNs); setErr != nil {
			if conn != nil {
				conn.Close()
			}
			resultCh <- dialResult{nil, fmt.Errorf("restore netns: %w", setErr)}
			return
		}

		resultCh <- dialResult{conn, err}
	}()

	result := <-resultCh
	return result.conn, result.err
}

// openNetnsViaHostMountNs opens a network namespace file by accessing it through
// PID 1's root filesystem view. This is necessary when running in a container with
// hostPID but separate mount namespace, where netns bind mounts are only visible
// from the host's filesystem.
func openNetnsViaHostMountNs(nsPath string) (netns.NsHandle, error) {
	// First try directly - might work if mount propagation is configured
	handle, err := netns.GetFromPath(nsPath)
	if err == nil {
		return handle, nil
	}

	// Access the netns through PID 1's root filesystem view.
	// This allows us to see files that are visible in the host's mount namespace
	// without actually switching our mount namespace (which causes issues with
	// file descriptor validity across namespace boundaries).
	pid1RootPath := filepath.Join("/proc/1/root", nsPath)
	handle, err = netns.GetFromPath(pid1RootPath)
	if err != nil {
		return 0, fmt.Errorf("open netns via /proc/1/root: %w", err)
	}

	return handle, nil
}

// findNetnsViaProcSearch finds a network namespace by searching /proc for a process
// belonging to the given pod UID. This works when we have hostPID but can't access
// /var/run/netns bind mounts due to mount namespace isolation.
func findNetnsViaProcSearch(targetNsPath string) (netns.NsHandle, error) {
	// This function is not used anymore - we use findNetnsForPodUID instead
	return 0, fmt.Errorf("deprecated: use findNetnsForPodUID instead")
}

// findNetnsForPodUID finds the network namespace for a pod by searching /proc for
// a process whose cgroup contains the pod UID. Returns an open handle to the netns.
func findNetnsForPodUID(podUID string) (netns.NsHandle, error) {
	if podUID == "" {
		return 0, fmt.Errorf("empty pod UID")
	}

	// Normalize pod UID format (remove dashes for comparison)
	normalizedUID := strings.ReplaceAll(podUID, "-", "_")
	// Also try with "pod" prefix (kubepods format)
	podPrefixUID := "pod" + podUID

	// Try multiple proc paths:
	// 1. /proc - direct access (works with hostPID)
	// 2. /proc/1/root/proc - host's proc view (works in k3s-in-Docker)
	procPaths := []string{"/proc", "/proc/1/root/proc"}

	var scannedCount int
	var debugSamples []string
	for _, procPath := range procPaths {
		entries, err := os.ReadDir(procPath)
		if err != nil {
			log.Printf("tunnel: findNetnsForPodUID: cannot read %s: %v", procPath, err)
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			// Skip non-numeric entries (they're not PIDs)
			pid := entry.Name()
			if len(pid) == 0 || pid[0] < '1' || pid[0] > '9' {
				continue
			}
			scannedCount++

			// Check if this process belongs to our pod by looking at its cgroup
			cgroupPath := filepath.Join(procPath, pid, "cgroup")
			cgroup, err := os.ReadFile(cgroupPath)
			if err != nil {
				continue
			}
			cgroupStr := string(cgroup)

			// Collect debug samples (first few cgroups we see)
			if len(debugSamples) < 3 && strings.Contains(cgroupStr, "kubepods") {
				debugSamples = append(debugSamples, fmt.Sprintf("pid=%s cgroup=%s", pid, strings.TrimSpace(cgroupStr)))
			}

			// Look for the pod UID in the cgroup path
			// Kubernetes cgroups typically include the pod UID in various formats:
			// - pod<uid> (kubepods/pod<uid>)
			// - <uid> (with dashes)
			// - <uid> (with dashes replaced by underscores)
			if !strings.Contains(cgroupStr, podUID) &&
			   !strings.Contains(cgroupStr, normalizedUID) &&
			   !strings.Contains(cgroupStr, podPrefixUID) {
				continue
			}

			// Found a process in this pod - open its network namespace
			// Use the same procPath for accessing ns/net
			netnsPath := filepath.Join(procPath, pid, "ns", "net")
			handle, err := netns.GetFromPath(netnsPath)
			if err != nil {
				log.Printf("tunnel: found pid %s for pod %s in %s but failed to open netns: %v", pid, podUID, procPath, err)
				continue
			}

			log.Printf("tunnel: found netns for pod %s via pid %s (proc: %s)", podUID, pid, procPath)
			return handle, nil
		}
	}

	// Log debug info if we couldn't find the pod
	if len(debugSamples) > 0 {
		log.Printf("tunnel: debug: sample cgroups seen: %v", debugSamples)
	}
	log.Printf("tunnel: debug: searching for podUID=%s normalizedUID=%s podPrefixUID=%s", podUID, normalizedUID, podPrefixUID)
	return 0, fmt.Errorf("no process found for pod UID %s (scanned %d PIDs)", podUID, scannedCount)
}
