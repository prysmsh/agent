//go:build !linux

package main

import "context"

type netnsListenerManager struct {
	t *tunnelDaemon
}

func newNetnsListenerManager(t *tunnelDaemon) *netnsListenerManager {
	return &netnsListenerManager{t: t}
}

func (m *netnsListenerManager) Start(ctx context.Context) error {
	// TPROXY and netns listeners are Linux-only
	return nil
}
