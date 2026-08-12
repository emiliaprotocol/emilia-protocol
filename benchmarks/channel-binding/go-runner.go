// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"time"
)

const label = "EXPERIMENTAL EMILIA channel binding benchmark v1"

type counts struct {
	TLSHandshakes      int `json:"tls_handshakes"`
	ExporterCalls      int `json:"exporter_calls"`
	HMACs              int `json:"hmacs"`
	ReplayStoreInserts int `json:"replay_store_inserts"`
}

type latency struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	P99 float64 `json:"p99"`
}

type result struct {
	Variant                string         `json:"variant"`
	Concurrency            int            `json:"concurrency"`
	Samples                int            `json:"samples"`
	LatencyUS              latency        `json:"latency_us"`
	CPUUS                  int64          `json:"cpu_us"`
	AllocatedBytesEstimate uint64         `json:"allocated_bytes_estimate"`
	AllocationMeasurement  string         `json:"allocation_measurement"`
	LockContention         map[string]any `json:"lock_contention"`
	OperationCounts        counts         `json:"operation_counts"`
}

type stackReport struct {
	Stack   string   `json:"stack"`
	Runtime string   `json:"runtime"`
	Results []result `json:"results"`
}

func processCPUUS() int64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	return usage.Utime.Sec*1_000_000 + int64(usage.Utime.Usec) + usage.Stime.Sec*1_000_000 + int64(usage.Stime.Usec)
}

func percentile(values []time.Duration, fraction float64) float64 {
	copyOf := append([]time.Duration(nil), values...)
	sort.Slice(copyOf, func(i, j int) bool { return copyOf[i] < copyOf[j] })
	index := int(float64(len(copyOf))*fraction+0.999999) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(copyOf) {
		index = len(copyOf) - 1
	}
	return float64(copyOf[index].Nanoseconds()) / 1_000
}

func summarize(variant string, concurrency, samples int, latencies []time.Duration, cpuBefore int64, allocBefore uint64, c counts) result {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return result{
		Variant: variant, Concurrency: concurrency, Samples: samples,
		LatencyUS:              latency{P50: percentile(latencies, .50), P95: percentile(latencies, .95), P99: percentile(latencies, .99)},
		CPUUS:                  processCPUUS() - cpuBefore,
		AllocatedBytesEstimate: memory.TotalAlloc - allocBefore,
		AllocationMeasurement:  "runtime_total_alloc_delta",
		LockContention:         map[string]any{"measurement": "not_available", "reason": "Go exposes no scoped per-operation lock-contention counter."},
		OperationCounts:        c,
	}
}

func dial(address string) (*tls.Conn, error) {
	return tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}) // test-only local certificate
}

func runConcurrent(samples, concurrency int, operation func(int) (time.Duration, error)) ([]time.Duration, error) {
	latencies := make([]time.Duration, samples)
	semaphore := make(chan struct{}, concurrency)
	errors := make(chan error, samples)
	var wait sync.WaitGroup
	for index := 0; index < samples; index++ {
		wait.Add(1)
		semaphore <- struct{}{}
		go func(i int) {
			defer wait.Done()
			defer func() { <-semaphore }()
			measured, err := operation(i)
			if err != nil {
				errors <- err
				return
			}
			latencies[i] = measured
		}(index)
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		return nil, err
	}
	return latencies, nil
}

func baseline(address string, concurrency, samples int) (result, error) {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	cpuBefore := processCPUUS()
	latencies, err := runConcurrent(samples, concurrency, func(index int) (time.Duration, error) {
		start := time.Now()
		connection, err := dial(address)
		if err != nil {
			return 0, err
		}
		defer connection.Close()
		context := make([]byte, 32)
		binary.BigEndian.PutUint32(context[28:], uint32(index))
		state := connection.ConnectionState()
		_, err = state.ExportKeyingMaterial(label, context, 32)
		return time.Since(start), err
	})
	if err != nil {
		return result{}, err
	}
	return summarize("rfc9266-connection-per-instance", concurrency, samples, latencies, cpuBefore, memory.TotalAlloc, counts{TLSHandshakes: samples, ExporterCalls: samples}), nil
}

func exporterContext(address string, concurrency, samples int) (result, error) {
	connection, err := dial(address)
	if err != nil {
		return result{}, err
	}
	defer connection.Close()
	state := connection.ConnectionState()
	var consumed sync.Map
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	cpuBefore := processCPUUS()
	latencies, err := runConcurrent(samples, concurrency, func(index int) (time.Duration, error) {
		context := make([]byte, 32)
		binary.BigEndian.PutUint32(context[28:], uint32(index))
		start := time.Now()
		_, err := state.ExportKeyingMaterial(label, context, 32)
		consumed.Store(index, true)
		return time.Since(start), err
	})
	if err != nil {
		return result{}, err
	}
	return summarize("nonce-in-exporter-context", concurrency, samples, latencies, cpuBefore, memory.TotalAlloc, counts{TLSHandshakes: 1, ExporterCalls: samples, ReplayStoreInserts: samples}), nil
}

func nonceInMessage(address string, concurrency, samples int) (result, error) {
	connection, err := dial(address)
	if err != nil {
		return result{}, err
	}
	defer connection.Close()
	state := connection.ConnectionState()
	key, err := state.ExportKeyingMaterial(label, []byte{}, 32)
	if err != nil {
		return result{}, err
	}
	var consumed sync.Map
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	cpuBefore := processCPUUS()
	latencies, err := runConcurrent(samples, concurrency, func(index int) (time.Duration, error) {
		frame := make([]byte, 114)
		binary.BigEndian.PutUint32(frame[2:], uint32(index))
		start := time.Now()
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(frame)
		_ = mac.Sum(nil)
		consumed.Store(index, true)
		return time.Since(start), nil
	})
	for index := range key {
		key[index] = 0
	}
	if err != nil {
		return result{}, err
	}
	return summarize("nonce-in-message", concurrency, samples, latencies, cpuBefore, memory.TotalAlloc, counts{TLSHandshakes: 1, ExporterCalls: 1, HMACs: samples, ReplayStoreInserts: samples}), nil
}

func main() {
	certPath := flag.String("cert", "", "TLS certificate")
	keyPath := flag.String("key", "", "TLS private key")
	concurrency := flag.Int("concurrency", 0, "concurrent instances")
	samples := flag.Int("samples", 0, "sample count")
	flag.Parse()
	if *certPath == "" || *keyPath == "" || *concurrency < 1 || *samples < 1 {
		fmt.Fprintln(os.Stderr, "invalid arguments")
		os.Exit(2)
	}
	certificate, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		panic(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tlsConnection, ok := c.(*tls.Conn); ok {
					_ = tlsConnection.Handshake()
				}
				buffer := make([]byte, 1)
				_, _ = c.Read(buffer)
			}(connection)
		}
	}()
	address := listener.Addr().String()
	results := make([]result, 0, 3)
	for _, runner := range []func(string, int, int) (result, error){baseline, exporterContext, nonceInMessage} {
		measured, err := runner(address, *concurrency, *samples)
		if err != nil {
			panic(err)
		}
		results = append(results, measured)
	}
	report := stackReport{Stack: "go-crypto-tls", Runtime: runtime.Version(), Results: results}
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(report); err != nil {
		panic(err)
	}
}
