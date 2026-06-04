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
	"log/slog"
	"net/http"
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/promslog/flag"
	"github.com/prometheus/common/version"
	"github.com/treydock/ssh_exporter/collector"
	"github.com/treydock/ssh_exporter/config"
)

const (
	sshEndpoint     = "/ssh"
	metricsEndpoint = "/metrics"
)

var (
	configFile    = kingpin.Flag("config.file", "Path to exporter config file").Default("ssh_exporter.yaml").String()
	listenAddress = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9312").String()
)

func metricsHandler(c *config.Config, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		registry := prometheus.NewRegistry()

		t := r.URL.Query().Get("target")
		if t == "" {
			http.Error(w, "'target' parameter must be specified", http.StatusBadRequest)
			return
		}
		m := r.URL.Query().Get("module")
		if m == "" {
			m = "default"
		}
		module, ok := c.Modules[m]
		if !ok {
			http.Error(w, fmt.Sprintf("Unknown module %s", t), http.StatusNotFound)
			return
		}
		logger.Debug("Loaded module", "module", module.ModuleName)

		target := &config.Target{
			Host:              t,
			User:              module.User,
			Password:          module.Password,
			PrivateKey:        module.PrivateKey,
			Certificate:       module.Certificate,
			KnownHosts:        module.KnownHosts,
			HostKeyAlgorithms: module.HostKeyAlgorithms,
			Timeout:           module.Timeout,
			Command:           module.Command,
			CommandExpect:     module.CommandExpect,
			OutputMetric:      module.OutputMetric,
			OutputTruncate:    module.OutputTruncate,
		}
		sshCollector := collector.NewCollector(target, logger.With("target", target.Host))
		registry.MustRegister(sshCollector)

		gatherers := prometheus.Gatherers{registry}

		// Delegate http serving to Prometheus client library, which will call collector.Collect.
		h := promhttp.HandlerFor(gatherers, promhttp.HandlerOpts{})
		h.ServeHTTP(w, r)
	}
}

func run(logger *slog.Logger) {
	logger.Info("Starting ssh_exporter", "version", version.Info())
	logger.Info("Build context", "build_context", version.BuildContext())
	logger.Info("Starting Server", "address", *listenAddress)

	sc := &config.SafeConfig{}

	if err := sc.ReloadConfig(*configFile); err != nil {
		logger.Error("Error loading config", "err", err)
		os.Exit(1)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		//nolint:errcheck
		w.Write([]byte(`<html>
             <head><title>SSH Exporter</title></head>
             <body>
             <h1>SSH Exporter</h1>
             <p><a href='` + sshEndpoint + `'>SSH Metrics</a></p>
             <p><a href='` + metricsEndpoint + `'>Exporter Metrics</a></p>
             </body>
             </html>`))
	})
	http.Handle(sshEndpoint, metricsHandler(sc.C, logger))
	http.Handle(metricsEndpoint, promhttp.Handler())
	err := http.ListenAndServe(*listenAddress, nil)
	if err != nil {
		logger.Error("Server error", "err", err)
		os.Exit(1)
	}
}

func main() {
	promslogConfig := &promslog.Config{}
	flag.AddFlags(kingpin.CommandLine, promslogConfig)
	kingpin.Version(version.Print("ssh_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	logger := promslog.New(promslogConfig)

	run(logger)
}
