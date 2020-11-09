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
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/gliderlabs/ssh"
	"github.com/go-kit/kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/treydock/ssh_exporter/config"
)

const (
	listen = 60022
)

func publicKeyHandler(ctx ssh.Context, key ssh.PublicKey) bool {
	buffer, err := ioutil.ReadFile("testdata/id_rsa_test1.pub")
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
		_, _ = io.WriteString(s, "foobar\n")
	})

	s := &ssh.Server{
		Addr:             fmt.Sprintf(":%d", listen),
		PublicKeyHandler: publicKeyHandler,
		PasswordHandler:  passwordHandler,
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
		"ssh_success", "ssh_failure"); err != nil {
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
		Command:       "echo 0",
		CommandExpect: "foo",
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
		"ssh_success", "ssh_failure"); err != nil {
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
		Command:       "echo 0",
		CommandExpect: "test",
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
		"ssh_success", "ssh_failure"); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
}

func TestCollectorTimeout(t *testing.T) {
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
		"ssh_success", "ssh_failure"); err != nil {
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
		"ssh_success", "ssh_failure"); err != nil {
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
		"ssh_success", "ssh_failure"); err != nil {
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
