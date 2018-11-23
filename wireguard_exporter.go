package main

import (
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const port = "9101"

func init() {
	prometheus.MustRegister(wireguardCollector{})
}

func main() {
	http.Handle("/metrics", promhttp.Handler())

	log.Printf("Starting server on port %s", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}

type wireguardCollector struct{}

var _ prometheus.Collector = (*wireguardCollector)(nil)

var (
	latestHandshakeDesc = prometheus.NewDesc(
		prometheus.BuildFQName("wireguard", "", "latest_handshake_age_seconds"),
		"Time in seconds since the latest handshake.",
		[]string{"interface", "public_key", "allowed_ips"},
		nil,
	)
	transferRxDesc = prometheus.NewDesc(
		prometheus.BuildFQName("wireguard", "", "transfer_rx_bytes"),
		"Number of received bytes.",
		[]string{"interface", "public_key", "allowed_ips"},
		nil,
	)
	transferTxDesc = prometheus.NewDesc(
		prometheus.BuildFQName("wireguard", "", "transfer_tx_bytes"),
		"Number of sent bytes.",
		[]string{"interface", "public_key", "allowed_ips"},
		nil,
	)
)

func (c wireguardCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- transferRxDesc
	ch <- transferTxDesc
}

func (c wireguardCollector) Collect(ch chan<- prometheus.Metric) {
	cmd := exec.Command("wg", "show", "all", "dump")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Error while calling wg: %s", err)
		return
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 9 {
			log.Printf("Error while splitting line '%s': unexpected number of fields", line)
			continue
		}

		labels := []string{fields[0], fields[1], fields[4]}

		latestHandshakeValue, err := strconv.ParseInt(fields[5], 10, 64)
		if err == nil {
			latestHandshakeAge := float64(time.Now().Unix() - latestHandshakeValue)
			ch <- prometheus.MustNewConstMetric(latestHandshakeDesc, prometheus.CounterValue, latestHandshakeAge, labels...)
		} else { // TODO: Handle 0 for missing data
			log.Printf("Error while parsing latest handshake '%s': %s", fields[5], err)
		}

		transferRxValue, err := strconv.ParseFloat(fields[6], 64)
		if err == nil {
			ch <- prometheus.MustNewConstMetric(transferRxDesc, prometheus.CounterValue, transferRxValue, labels...)
		} else {
			log.Printf("Error while parsing transfer rx '%s': %s", fields[6], err)
		}

		transferTxValue, err := strconv.ParseFloat(fields[7], 64)
		if err == nil {
			ch <- prometheus.MustNewConstMetric(transferTxDesc, prometheus.CounterValue, transferTxValue, labels...)
		} else {
			log.Printf("Error while parsing transfer tx '%s': %s", fields[7], err)
		}
	}
}

type wgStats struct {
	wgInterface string
	publicKey   string
	allowedIps  string
}

func newWgState(line string) (wgStats, error) {
	fields := strings.Split(line, "\t")
	if len(fields) != 9 {
		return wgStats{}, fmt.Errorf("unexpected number of fields: %d", len(fields))
	}

	return wgStats{
		wgInterface: fields[0],
	}, nil
}

//func reportLatestHandshake(ch chan<- prometheus.Metric)
