// Copyright 2020 Trey Dockendorf
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/gliderlabs/ssh"
	"github.com/go-kit/kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/treydock/ssh_exporter/config"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	listen = 60022
)

var knownHosts *os.File

func publicKeyHandler(ctx ssh.Context, key ssh.PublicKey) bool {
	buffer, err := os.ReadFile("testdata/id_rsa_test1.pub")
	if err != nil {
		fmt.Printf("ERROR reading public key testdata/id_rsa_test1.pub: %s", err)
		os.Exit(1)
	}
	goodKey, _, _, _, err := ssh.ParseAuthorizedKey(buffer)
	if err != nil {
		fmt.Printf("ERROR parsing public key testdata/id_rsa_test1.pub: %s", err)
		os.Exit(1)
	}

	if ssh.KeysEqual(key, goodKey) {
		return true
	} else {
		return false
	}
}

func passwordHandler(ctx ssh.Context, password string) bool {
	if password == "test" {
		return true
	} else {
		return false
	}
}

func TestMain(m *testing.M) {
	ssh.Handle(func(s ssh.Session) {
		_, _ = io.WriteString(s, "11:42:20 up 57 days, 19:18,  5 users,  load average: 2.48, 1.10, 0.49\n")
	})

	s := &ssh.Server{
		Addr:             fmt.Sprintf(":%d", listen),
		PublicKeyHandler: publicKeyHandler,
		PasswordHandler:  passwordHandler,
	}
	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("ERROR generating RSA host key: %s", err)
		os.Exit(1)
	}
	signer, err := gossh.NewSignerFromKey(hostKey)
	if err != nil {
		fmt.Printf("ERROR generating host key signer: %s", err)
		os.Exit(1)
	}
	s.AddHostKey(signer)
	knownHosts, err = os.CreateTemp("", "knowm_hosts")
	if err != nil {
		fmt.Printf("ERROR creating known hosts: %s", err)
		os.Exit(1)
	}
	defer os.Remove(knownHosts.Name())
	knownHostsLine := knownhosts.Line([]string{fmt.Sprintf("localhost:%d", listen)}, s.HostSigners[0].PublicKey())
	if _, err = knownHosts.Write([]byte(knownHostsLine)); err != nil {
		fmt.Printf("ERROR writing known hosts: %s", err)
	}
	go func() {
		if err := s.ListenAndServe(); err != nil {
			fmt.Printf("ERROR starting SSH server: %s", err)
			os.Exit(1)
		}
	}()

	exitVal := m.Run()

	os.Exit(exitVal)
}

func TestCollector(t *testing.T) {
	expected := `
	# HELP ssh_failure Indicates a failure
	# TYPE ssh_failure gauge
	ssh_failure{reason="command-error"} 0
	ssh_failure{reason="command-output"} 0
	ssh_failure{reason="error"} 0
	ssh_failure{reason="timeout"} 0
	# HELP ssh_success SSH connection was successful
	# TYPE ssh_success gauge
	ssh_success 1
	`
	target := &config.Target{
		Host:     fmt.Sprintf("localhost:%d", listen),
		User:     "test",
		Password: "test",
		Timeout:  2,
	}
	w := log.NewSyncWriter(os.Stderr)
	logger := log.NewLogfmtLogger(w)
	collector := NewCollector(target, logger)
	gatherers := setupGatherer(collector)
	if val, err := testutil.GatherAndCount(gatherers); err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if val != 6 {
		t.Errorf("Unexpected collection count %d, expected 6", val)
	}
	if err := testutil.GatherAndCompare(gatherers, strings.NewReader(expected),
		"ssh_success", "ssh_failure", "ssh_output"); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
}

func TestCollectorCommand(t *testing.T) {
	expected := `
	# HELP ssh_failure Indicates a failure
	# TYPE ssh_failure gauge
	ssh_failure{reason="command-error"} 0
	ssh_failure{reason="command-output"} 0
	ssh_failure{reason="error"} 0
	ssh_failure{reason="timeout"} 0
	# HELP ssh_success SSH connection was successful
	# TYPE ssh_success gauge
	ssh_success 1
	`
	target := &config.Target{
		Host:          fmt.Sprintf("localhost:%d", listen),
		User:          "test",
		Password:      "test",
		Command:       "uptime",
		CommandExpect: "load average",
		Timeout:       2,
	}
	w := log.NewSyncWriter(os.Stderr)
	logger := log.NewLogfmtLogger(w)
	collector := NewCollector(target, logger)
	gatherers := setupGatherer(collector)
	if val, err := testutil.GatherAndCount(gatherers); err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if val != 6 {
		t.Errorf("Unexpected collection count %d, expected 6", val)
	}
	if err := testutil.GatherAndCompare(gatherers, strings.NewReader(expected),
		"ssh_success", "ssh_failure", "ssh_output"); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
}

func TestCollectorCommandOutputMetric(t *testing.T) {
	expected := `
	# HELP ssh_failure Indicates a failure
	# TYPE ssh_failure gauge
	ssh_failure{reason="command-error"} 0
	ssh_failure{reason="command-output"} 0
	ssh_failure{reason="error"} 0
	ssh_failure{reason="timeout"} 0
	# HELP ssh_output The output of the executed command
	# TYPE ssh_output gauge
	ssh_output{output="11:42:20 up 57 days, 19:18,  5 users,  load ave..."} 1
	# HELP ssh_success SSH connection was successful
	# TYPE ssh_success gauge
	ssh_success 1
	`
	target := &config.Target{
		Host:           fmt.Sprintf("localhost:%d", listen),
		User:           "test",
		Password:       "test",
		Command:        "uptime",
		CommandExpect:  "load average",
		OutputMetric:   true,
		OutputTruncate: 50,
		Timeout:        2,
	}
	w := log.NewSyncWriter(os.Stderr)
	logger := log.NewLogfmtLogger(w)
	collector := NewCollector(target, logger)
	gatherers := setupGatherer(collector)
	if val, err := testutil.GatherAndCount(gatherers); err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if val != 7 {
		t.Errorf("Unexpected collection count %d, expected 7", val)
	}
	if err := testutil.GatherAndCompare(gatherers, strings.NewReader(expected),
		"ssh_success", "ssh_failure", "ssh_output"); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
}

func TestCollectorCommandOutputMetricNoTruncate(t *testing.T) {
	expected := `
	# HELP ssh_failure Indicates a failure
	# TYPE ssh_failure gauge
	ssh_failure{reason="command-error"} 0
	ssh_failure{reason="command-output"} 0
	ssh_failure{reason="error"} 0
	ssh_failure{reason="timeout"} 0
	# HELP ssh_output The output of the executed command
	# TYPE ssh_output gauge
	ssh_output{output="11:42:20 up 57 days, 19:18,  5 users,  load average: 2.48, 1.10, 0.49"} 1
	# HELP ssh_success SSH connection was successful
	# TYPE ssh_success gauge
	ssh_success 1
	`
	target := &config.Target{
		Host:           fmt.Sprintf("localhost:%d", listen),
		User:           "test",
		Password:       "test",
		Command:        "uptime",
		CommandExpect:  "load average",
		OutputMetric:   true,
		OutputTruncate: -1,
		Timeout:        2,
	}
	w := log.NewSyncWriter(os.Stderr)
	logger := log.NewLogfmtLogger(w)
	collector := NewCollector(target, logger)
	gatherers := setupGatherer(collector)
	if val, err := testutil.GatherAndCount(gatherers); err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if val != 7 {
		t.Errorf("Unexpected collection count %d, expected 7", val)
	}
	if err := testutil.GatherAndCompare(gatherers, strings.NewReader(expected),
		"ssh_success", "ssh_failure", "ssh_output"); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
}

func TestCollectorCommandOutputError(t *testing.T) {
	expected := `
	# HELP ssh_failure Indicates a failure
	# TYPE ssh_failure gauge
	ssh_failure{reason="command-error"} 0
	ssh_failure{reason="command-output"} 1
	ssh_failure{reason="error"} 0
	ssh_failure{reason="timeout"} 0
	# HELP ssh_success SSH connection was successful
	# TYPE ssh_success gauge
	ssh_success 0
	`
	target := &config.Target{
		Host:          fmt.Sprintf("localhost:%d", listen),
		User:          "test",
		Password:      "test",
		Command:       "uptime",
		CommandExpect: "foobar",
		Timeout:       2,
	}
	collector := NewCollector(target, log.NewNopLogger())
	gatherers := setupGatherer(collector)
	if val, err := testutil.GatherAndCount(gatherers); err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if val != 6 {
		t.Errorf("Unexpected collection count %d, expected 6", val)
	}
	if err := testutil.GatherAndCompare(gatherers, strings.NewReader(expected),
		"ssh_success", "ssh_failure", "ssh_output"); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
}

func TestCollectorTimeoutDial(t *testing.T) {
	expected := `
	# HELP ssh_failure Indicates a failure
	# TYPE ssh_failure gauge
	ssh_failure{reason="command-error"} 0
	ssh_failure{reason="command-output"} 0
	ssh_failure{reason="error"} 0
	ssh_failure{reason="timeout"} 1
	# HELP ssh_success SSH connection was successful
	# TYPE ssh_success gauge
	ssh_success 0
	`
	target := &config.Target{
		Host:     fmt.Sprintf("localhost:%d", listen),
		User:     "test",
		Password: "test",
		Timeout:  -2,
	}
	w := log.NewSyncWriter(os.Stderr)
	logger := log.NewLogfmtLogger(w)
	collector := NewCollector(target, logger)
	gatherers := setupGatherer(collector)
	if val, err := testutil.GatherAndCount(gatherers); err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if val != 6 {
		t.Errorf("Unexpected collection count %d, expected 6", val)
	}
	if err := testutil.GatherAndCompare(gatherers, strings.NewReader(expected),
		"ssh_success", "ssh_failure", "ssh_output"); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
}

func TestCollectorTimeoutCommand(t *testing.T) {
	expected := `
	# HELP ssh_failure Indicates a failure
	# TYPE ssh_failure gauge
	ssh_failure{reason="command-error"} 0
	ssh_failure{reason="command-output"} 0
	ssh_failure{reason="error"} 0
	ssh_failure{reason="timeout"} 1
	# HELP ssh_success SSH connection was successful
	# TYPE ssh_success gauge
	ssh_success 0
	`
	target := &config.Target{
		Host:     fmt.Sprintf("localhost:%d", listen),
		User:     "test",
		Password: "test",
		Command:  "sleep 1",
		Timeout:  0,
	}
	w := log.NewSyncWriter(os.Stderr)
	logger := log.NewLogfmtLogger(w)
	collector := NewCollector(target, logger)
	gatherers := setupGatherer(collector)
	if val, err := testutil.GatherAndCount(gatherers); err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if val != 6 {
		t.Errorf("Unexpected collection count %d, expected 6", val)
	}
	if err := testutil.GatherAndCompare(gatherers, strings.NewReader(expected),
		"ssh_success", "ssh_failure", "ssh_output"); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
}

func TestCollectorError(t *testing.T) {
	expected := `
	# HELP ssh_failure Indicates a failure
	# TYPE ssh_failure gauge
	ssh_failure{reason="command-error"} 0
	ssh_failure{reason="command-output"} 0
	ssh_failure{reason="error"} 1
	ssh_failure{reason="timeout"} 0
	# HELP ssh_success SSH connection was successful
	# TYPE ssh_success gauge
	ssh_success 0
	`
	target := &config.Target{
		Host:     fmt.Sprintf("localhost:%d", listen),
		User:     "test",
		Password: "foobar",
		Timeout:  2,
	}
	w := log.NewSyncWriter(os.Stderr)
	logger := log.NewLogfmtLogger(w)
	collector := NewCollector(target, logger)
	gatherers := setupGatherer(collector)
	if val, err := testutil.GatherAndCount(gatherers); err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if val != 6 {
		t.Errorf("Unexpected collection count %d, expected 6", val)
	}
	if err := testutil.GatherAndCompare(gatherers, strings.NewReader(expected),
		"ssh_success", "ssh_failure", "ssh_output"); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
}

func TestCollectorPrivateKey(t *testing.T) {
	expected := `
	# HELP ssh_failure Indicates a failure
	# TYPE ssh_failure gauge
	ssh_failure{reason="command-error"} 0
	ssh_failure{reason="command-output"} 0
	ssh_failure{reason="error"} 0
	ssh_failure{reason="timeout"} 0
	# HELP ssh_success SSH connection was successful
	# TYPE ssh_success gauge
	ssh_success 1
	`
	target := &config.Target{
		Host:       fmt.Sprintf("localhost:%d", listen),
		User:       "test",
		PrivateKey: "testdata/id_rsa_test1",
		Timeout:    2,
	}
	w := log.NewSyncWriter(os.Stderr)
	logger := log.NewLogfmtLogger(w)
	collector := NewCollector(target, logger)
	gatherers := setupGatherer(collector)
	if val, err := testutil.GatherAndCount(gatherers); err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if val != 6 {
		t.Errorf("Unexpected collection count %d, expected 6", val)
	}
	if err := testutil.GatherAndCompare(gatherers, strings.NewReader(expected),
		"ssh_success", "ssh_failure", "ssh_output"); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
}

func TestCollectorKnownHosts(t *testing.T) {
	expected := `
	# HELP ssh_failure Indicates a failure
	# TYPE ssh_failure gauge
	ssh_failure{reason="command-error"} 0
	ssh_failure{reason="command-output"} 0
	ssh_failure{reason="error"} 0
	ssh_failure{reason="timeout"} 0
	# HELP ssh_success SSH connection was successful
	# TYPE ssh_success gauge
	ssh_success 1
	`
	target := &config.Target{
		Host:       fmt.Sprintf("localhost:%d", listen),
		User:       "test",
		PrivateKey: "testdata/id_rsa_test1",
		KnownHosts: knownHosts.Name(),
		Timeout:    2,
	}
	w := log.NewSyncWriter(os.Stderr)
	logger := log.NewLogfmtLogger(w)
	collector := NewCollector(target, logger)
	gatherers := setupGatherer(collector)
	if val, err := testutil.GatherAndCount(gatherers); err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if val != 6 {
		t.Errorf("Unexpected collection count %d, expected 6", val)
	}
	if err := testutil.GatherAndCompare(gatherers, strings.NewReader(expected),
		"ssh_success", "ssh_failure", "ssh_output"); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
}

func TestCollectorKnownHostsError(t *testing.T) {
	expected := `
	# HELP ssh_failure Indicates a failure
	# TYPE ssh_failure gauge
	ssh_failure{reason="command-error"} 0
	ssh_failure{reason="command-output"} 0
	ssh_failure{reason="error"} 1
	ssh_failure{reason="timeout"} 0
	# HELP ssh_success SSH connection was successful
	# TYPE ssh_success gauge
	ssh_success 0
	`
	target := &config.Target{
		Host:       fmt.Sprintf("127.0.0.1:%d", listen),
		User:       "test",
		PrivateKey: "testdata/id_rsa_test1",
		KnownHosts: knownHosts.Name(),
		Timeout:    2,
	}
	w := log.NewSyncWriter(os.Stderr)
	logger := log.NewLogfmtLogger(w)
	collector := NewCollector(target, logger)
	gatherers := setupGatherer(collector)
	if val, err := testutil.GatherAndCount(gatherers); err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if val != 6 {
		t.Errorf("Unexpected collection count %d, expected 6", val)
	}
	if err := testutil.GatherAndCompare(gatherers, strings.NewReader(expected),
		"ssh_success", "ssh_failure", "ssh_output"); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
}

func TestCollectorKnownHostsDNE(t *testing.T) {
	expected := `
	# HELP ssh_failure Indicates a failure
	# TYPE ssh_failure gauge
	ssh_failure{reason="command-error"} 0
	ssh_failure{reason="command-output"} 0
	ssh_failure{reason="error"} 1
	ssh_failure{reason="timeout"} 0
	# HELP ssh_success SSH connection was successful
	# TYPE ssh_success gauge
	ssh_success 0
	`
	target := &config.Target{
		Host:       fmt.Sprintf("localhost:%d", listen),
		User:       "test",
		PrivateKey: "testdata/id_rsa_test1",
		KnownHosts: "/dne",
		Timeout:    2,
	}
	w := log.NewSyncWriter(os.Stderr)
	logger := log.NewLogfmtLogger(w)
	collector := NewCollector(target, logger)
	gatherers := setupGatherer(collector)
	if val, err := testutil.GatherAndCount(gatherers); err != nil {
		t.Errorf("Unexpected error: %v", err)
	} else if val != 6 {
		t.Errorf("Unexpected collection count %d, expected 6", val)
	}
	if err := testutil.GatherAndCompare(gatherers, strings.NewReader(expected),
		"ssh_success", "ssh_failure", "ssh_output"); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
}

func TestCollectDNEKey(t *testing.T) {
	target := &config.Target{
		Host:       fmt.Sprintf("localhost:%d", listen),
		User:       "test",
		PrivateKey: "testdata/dne",
		Timeout:    2,
	}
	w := log.NewSyncWriter(os.Stderr)
	logger := log.NewLogfmtLogger(w)
	collector := NewCollector(target, logger)
	metric := collector.collect()
	if metric.FailureReason != "error" {
		t.Errorf("Expected failure reason to be error, got %s", metric.FailureReason)
	}
}

func TestCollectBadKey(t *testing.T) {
	target := &config.Target{
		Host:       fmt.Sprintf("localhost:%d", listen),
		User:       "test",
		PrivateKey: "testdata/id_rsa_test1.pub",
		Timeout:    2,
	}
	w := log.NewSyncWriter(os.Stderr)
	logger := log.NewLogfmtLogger(w)
	collector := NewCollector(target, logger)
	metric := collector.collect()
	if metric.FailureReason != "error" {
		t.Errorf("Expected failure reason to be error, got %s", metric.FailureReason)
	}
}

func setupGatherer(collector *Collector) prometheus.Gatherer {
	registry := prometheus.NewRegistry()
	registry.MustRegister(collector)
	gatherers := prometheus.Gatherers{registry}
	return gatherers
}
