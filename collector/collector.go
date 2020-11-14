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
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/treydock/ssh_exporter/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	namespace = "ssh"
)

type Metric struct {
	Success       float64
	FailureReason string
}

type Collector struct {
	Success  *prometheus.Desc
	Duration *prometheus.Desc
	Failure  *prometheus.Desc
	target   *config.Target
	logger   log.Logger
}

func NewCollector(target *config.Target, logger log.Logger) *Collector {
	return &Collector{
		Success: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "success"),
			"SSH connection was successful", nil, nil),
		Duration: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "duration_seconds"),
			"How long the SSH check took in seconds", nil, nil),
		Failure: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "failure"),
			"Indicates a failure", []string{"reason"}, nil),
		target: target,
		logger: logger,
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.Success
	ch <- c.Duration
	ch <- c.Failure
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	level.Debug(c.logger).Log("msg", "Collecting SSH metrics")
	failureReasons := []string{"error", "timeout", "command-error", "command-output"}
	collectTime := time.Now()

	metric := c.collect()

	ch <- prometheus.MustNewConstMetric(c.Success, prometheus.GaugeValue, metric.Success)
	for _, reason := range failureReasons {
		var value float64
		if reason == metric.FailureReason {
			value = 1
		} else {
			value = 0
		}
		ch <- prometheus.MustNewConstMetric(c.Failure, prometheus.GaugeValue, value, reason)
	}
	ch <- prometheus.MustNewConstMetric(c.Duration, prometheus.GaugeValue, time.Since(collectTime).Seconds())
}

func (c *Collector) collect() Metric {
	c1 := make(chan int, 1)
	timeout := false
	var metric Metric
	var auth ssh.AuthMethod
	var sessionerror, autherror, commanderror error
	var commandOutput string

	if c.target.PrivateKey != "" {
		auth, autherror = getPrivateKeyAuth(c.target.PrivateKey)
		if autherror != nil {
			metric.FailureReason = "error"
			level.Error(c.logger).Log("msg", "Error setting up private key auth", "err", autherror)
			return metric
		}
	} else {
		auth = ssh.Password(c.target.Password)
	}

	sshConfig := &ssh.ClientConfig{
		User:            c.target.User,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: hostKeyCallback(&metric, c.target, c.logger),
		Timeout:         time.Duration(c.target.Timeout) * time.Second,
	}
	connection, err := ssh.Dial("tcp", c.target.Host, sshConfig)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			metric.FailureReason = "timeout"
		} else {
			metric.FailureReason = "error"
		}
		level.Error(c.logger).Log("msg", "Failed to establish SSH connection", "err", err)
		return metric
	}
	defer connection.Close()

	go func(conn *ssh.Client) {
		var session *ssh.Session
		session, sessionerror = conn.NewSession()
		if sessionerror != nil {
			return
		}
		defer session.Close()
		if c.target.Command != "" {
			var cmdBuffer bytes.Buffer
			session.Stdout = &cmdBuffer
			commanderror = session.Run(c.target.Command)
			if commanderror != nil {
				return
			}
			commandOutput = cmdBuffer.String()
		}
		if !timeout {
			c1 <- 1
		}
	}(connection)

	select {
	case <-c1:
	case <-time.After(time.Duration(c.target.Timeout) * time.Second):
		timeout = true
		close(c1)
		metric.FailureReason = "timeout"
		level.Error(c.logger).Log("msg", "Timeout establishing SSH session")
		return metric
	}
	close(c1)
	if sessionerror != nil {
		metric.FailureReason = "error"
		level.Error(c.logger).Log("msg", "Error establishing SSH session", "err", sessionerror)
		return metric
	}
	if commanderror != nil {
		metric.FailureReason = "command-error"
		level.Error(c.logger).Log("msg", "Error executing command", "err", commanderror, "command", c.target.Command)
		return metric
	}
	if c.target.Command != "" && c.target.CommandExpect != "" {
		commandExpectPattern := regexp.MustCompile(c.target.CommandExpect)
		if !commandExpectPattern.MatchString(commandOutput) {
			level.Error(c.logger).Log("msg", "Command output did not match expected value",
				"output", commandOutput, "command", c.target.Command)
			metric.FailureReason = "command-output"
			return metric
		}
	}
	metric.Success = 1
	return metric
}

func getPrivateKeyAuth(privatekey string) (ssh.AuthMethod, error) {
	buffer, err := ioutil.ReadFile(privatekey)
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(key), nil
}

func hostKeyCallback(metric *Metric, target *config.Target, logger log.Logger) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		var hostKeyCallback ssh.HostKeyCallback
		var err error
		if target.KnownHosts != "" {
			publicKey := base64.StdEncoding.EncodeToString(key.Marshal())
			level.Debug(logger).Log("msg", "Verify SSH known hosts", "hostname", hostname, "remote", remote.String(), "key", publicKey)
			hostKeyCallback, err = knownhosts.New(target.KnownHosts)
			if err != nil {
				metric.FailureReason = "error"
				level.Error(logger).Log("msg", "Error creating hostkeycallback function", "err", err)
				return err
			}
		} else {
			hostKeyCallback = ssh.InsecureIgnoreHostKey()
		}
		return hostKeyCallback(hostname, remote, key)
	}
}
