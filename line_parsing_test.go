package main

import (
	"strings"
	"testing"
)

// For this script-friendly display, if all is specified, then the first field for all categories of information is
// the interface name. If dump is specified, then several lines are printed; the first contains in order separated by
// tab:  private-key,  public-key,  listen-port, fwmark.
// Subsequent lines are printed for each peer and contain in order separated by tab: public-key, preshared-key,
// endpoint, allowed-ips, latest-handshake, transfer-rx, transfer-tx, persistent-keepalive.

func TestHandleInvalidFieldCount(t *testing.T) {
	testCases := map[string][]string{
		"empty string":         []string{},
		"almost enough fields": []string{"1", "2", "3", "4", "5", "6", "7", "8"},
	}

	for name, fields := range testCases {
		t.Run(name, func(t *testing.T) {
			line := strings.Join(fields, "\t")
			_, err := newWgState(line)
			if err == nil {
				t.Error("expected an error but got none")
			}
		})
	}
}

func TestNewWgState(t *testing.T) {
	line := strings.Join([]string{"interface-name", "public-key", "preshared-key", "endpoint", "allowed-ips", "latest-handshake", "transfer-rx", "transfer-tx", "persistent-keepalive"}, "\t")
	stats, err := newWgState(line)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	expectedStats := wgStats{
		wgInterface: "interface-name",
		//publicKey:   "public-key",
		//allowedIps:  "allowed-ips",
	}
	if expectedStats != stats {
		t.Errorf("expected state %s but got %s", expectedStats, stats)
	}
}
