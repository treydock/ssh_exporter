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
	"io/ioutil"
	"regexp"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/treydock/ssh_exporter/config"
	"golang.org/x/crypto/ssh"
)

const (
	namespace = "ssh"
)

type Metric struct {
	Success           bool
	Error             bool
	Timeout           bool
	CommandError      bool
	CommandExpectFail bool
}

type Collector struct {
	Success           *prometheus.Desc
	Duration          *prometheus.Desc
	Timeout           *prometheus.Desc
	Error             *prometheus.Desc
	CommandError      *prometheus.Desc
	CommandExpectFail *prometheus.Desc
	target            *config.Target
	logger            log.Logger
}

func NewCollector(target *config.Target, logger log.Logger) *Collector {
	return &Collector{
		Success: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "success"),
			"SSH connection was successful", nil, nil),
		Duration: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "duration_seconds"),
			"How long the SSH check took in seconds", nil, nil),
		Timeout: prometheus.NewDesc(prometheus.BuildFQName(namespace, "failure", "timeout"),
			"Indicates the failure was due to timeout", nil, nil),
		Error: prometheus.NewDesc(prometheus.BuildFQName(namespace, "failure", "error"),
			"Indicates the failure was due to an error", nil, nil),
		CommandError: prometheus.NewDesc(prometheus.BuildFQName(namespace, "failure", "command_error"),
			"Indicates the failure was due to an error executed the configured command", nil, nil),
		CommandExpectFail: prometheus.NewDesc(prometheus.BuildFQName(namespace, "failure", "command_output"),
			"Indicates the failure was due to command output not matching expected value", nil, nil),
		target: target,
		logger: logger,
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.Success
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	level.Debug(c.logger).Log("msg", "Collecting SSH metrics", "host", c.target.Host)
	collectTime := time.Now()

	metric := c.collect()

	ch <- prometheus.MustNewConstMetric(c.Success, prometheus.GaugeValue, boolToFloat64(metric.Success))
	ch <- prometheus.MustNewConstMetric(c.Timeout, prometheus.GaugeValue, boolToFloat64(metric.Timeout))
	ch <- prometheus.MustNewConstMetric(c.Error, prometheus.GaugeValue, boolToFloat64(metric.Error))
	ch <- prometheus.MustNewConstMetric(c.CommandError, prometheus.GaugeValue, boolToFloat64(metric.CommandError))
	ch <- prometheus.MustNewConstMetric(c.CommandExpectFail, prometheus.GaugeValue, boolToFloat64(metric.CommandExpectFail))
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
			metric.Error = true
			level.Error(c.logger).Log("msg", "Error setting up private key auth", "err", autherror, "host", c.target.Host)
			return metric
		}
	} else {
		auth = ssh.Password(c.target.Password)
	}

	sshConfig := &ssh.ClientConfig{
		User:            c.target.User,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(c.target.Timeout) * time.Second,
	}
	connection, err := ssh.Dial("tcp", c.target.Host, sshConfig)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			metric.Timeout = true
		} else {
			metric.Error = true
		}
		level.Error(c.logger).Log("msg", "Failed to establish SSH connection", "err", err, "host", c.target.Host)
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
	case <-time.After(time.Duration(c.target.Timeout+2) * time.Second):
		timeout = true
		close(c1)
		metric.Timeout = true
		level.Error(c.logger).Log("msg", "Timeout establishing SSH session", "host", c.target.Host)
		return metric
	}
	close(c1)
	if sessionerror != nil {
		metric.Error = true
		level.Error(c.logger).Log("msg", "Error establishing SSH session", "err", sessionerror, "host", c.target.Host)
		return metric
	}
	if commanderror != nil {
		metric.CommandError = true
		level.Error(c.logger).Log("msg", "Error executing command", "err", commanderror, "host", c.target.Host, "command", c.target.Command)
		return metric
	}
	if c.target.Command != "" && c.target.CommandExpect != "" {
		commandExpectPattern := regexp.MustCompile(c.target.CommandExpect)
		if !commandExpectPattern.MatchString(commandOutput) {
			level.Error(c.logger).Log("msg", "Command output did not match expected value",
				"output", commandOutput, "host", c.target.Host, "command", c.target.Command)
			metric.CommandExpectFail = true
			return metric
		}
	}
	metric.Success = true
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

func boolToFloat64(data bool) float64 {
	if data {
		return float64(1)
	} else {
		return float64(0)
	}
}
