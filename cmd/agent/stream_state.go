// Package main provides per-connection stream state for multi-chunk pattern detection.
// The StreamState accumulates a sliding window of recent bytes so that attack patterns
// split across TCP segment boundaries (e.g., "UNI" + "ON SELECT") are detected.
package main

import (
	"sync"
)

const (
	// DefaultStreamWindowSize is the default sliding window size (8KB).
	DefaultStreamWindowSize = 8192
)

// StreamState tracks per-connection state for multi-chunk inspection.
type StreamState struct {
	mu         sync.Mutex
	window     []byte // sliding window of recent bytes
	windowSize int    // max window capacity
	totalBytes int64  // total bytes seen on this connection
	firstChunk bool   // true until the first chunk is appended

	// HTTP state parsed from the stream
	httpState *HTTPStreamState

	// Alert deduplication: signature ID → already alerted
	alertedSigs map[string]bool
}

// HTTPStreamState tracks parsed HTTP request state from the stream.
type HTTPStreamState struct {
	Method  string
	Path    string
	Headers map[string]string
	SeenHTTP bool
}

// NewStreamState creates a new per-connection stream state.
func NewStreamState() *StreamState {
	return &StreamState{
		window:      make([]byte, 0, DefaultStreamWindowSize),
		windowSize:  DefaultStreamWindowSize,
		firstChunk:  true,
		alertedSigs: make(map[string]bool),
		httpState:   &HTTPStreamState{Headers: make(map[string]string)},
	}
}

// Append adds new data to the sliding window and returns the current window contents.
// If the window would exceed windowSize, older bytes are discarded.
func (ss *StreamState) Append(data []byte) []byte {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.totalBytes += int64(len(data))
	ss.firstChunk = false

	// Append new data
	ss.window = append(ss.window, data...)

	// Trim to sliding window size
	if len(ss.window) > ss.windowSize {
		excess := len(ss.window) - ss.windowSize
		ss.window = ss.window[excess:]
	}

	// Return a copy so callers can use it without holding the lock
	out := make([]byte, len(ss.window))
	copy(out, ss.window)
	return out
}

// HasAlerted returns true if we already fired an alert for this signature ID
// on this connection, and marks it as alerted if not.
func (ss *StreamState) HasAlerted(sigID string) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.alertedSigs[sigID] {
		return true
	}
	ss.alertedSigs[sigID] = false // will be set to true by MarkAlerted
	return false
}

// MarkAlerted marks a signature ID as having fired on this connection.
func (ss *StreamState) MarkAlerted(sigID string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.alertedSigs[sigID] = true
}

// TotalBytes returns the total bytes seen on this connection.
func (ss *StreamState) TotalBytes() int64 {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.totalBytes
}

// Window returns a copy of the current sliding window contents.
func (ss *StreamState) Window() []byte {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	out := make([]byte, len(ss.window))
	copy(out, ss.window)
	return out
}

// Reset clears the stream state for reuse.
func (ss *StreamState) Reset() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.window = ss.window[:0]
	ss.totalBytes = 0
	ss.firstChunk = true
	ss.alertedSigs = make(map[string]bool)
	ss.httpState = &HTTPStreamState{Headers: make(map[string]string)}
}
