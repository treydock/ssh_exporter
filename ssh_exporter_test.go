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

package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/gliderlabs/ssh"
	"github.com/go-kit/log"
)

const (
	address = "localhost:19312"
	sshPort = 60023
)

func TestMain(m *testing.M) {
	if _, err := kingpin.CommandLine.Parse([]string{"--config.file", "config/testdata/ssh_exporter.yaml", "--web.listen-address", address}); err != nil {
		fmt.Printf("ERROR parsing arguments %s", err)
		os.Exit(1)
	}
	ssh.Handle(func(s ssh.Session) {
		_, _ = io.WriteString(s, "foobar\n")
	})

	go func() {
		if err := ssh.ListenAndServe(fmt.Sprintf(":%d", sshPort), nil); err != nil {
			fmt.Printf("ERROR starting SSH server: %s", err)
			os.Exit(1)
		}
	}()
	w := log.NewSyncWriter(os.Stderr)
	logger := log.NewLogfmtLogger(w)
	go func() {
		run(logger)
	}()
	time.Sleep(1 * time.Second)

	exitVal := m.Run()

	os.Exit(exitVal)
}

func TestMetricsHandler(t *testing.T) {
	body, err := queryExporter(fmt.Sprintf("target=localhost:%d", sshPort), http.StatusOK)
	if err != nil {
		t.Fatalf("Unexpected error GET /ssh: %s", err.Error())
	}
	if !strings.Contains(body, "ssh_success 1") {
		t.Errorf("Unexpected value for ssh_success\nGot:\n%s", body)
	}
}

func TestMetricsHandlerNoTarget(t *testing.T) {
	_, _ = queryExporter("", http.StatusBadRequest)
}

func TestMetricsHandlerBadModule(t *testing.T) {
	_, _ = queryExporter(fmt.Sprintf("target=localhost:%d&module=dne", sshPort), http.StatusNotFound)
}

func queryExporter(param string, want int) (string, error) {
	resp, err := http.Get(fmt.Sprintf("http://%s/ssh?%s", address, param))
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if err := resp.Body.Close(); err != nil {
		return "", err
	}
	if have := resp.StatusCode; want != have {
		return "", fmt.Errorf("want /metrics status code %d, have %d. Body:\n%s", want, have, b)
	}
	return string(b), nil
}
