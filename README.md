[![Build Status](https://circleci.com/gh/treydock/ssh_exporter/tree/master.svg?style=shield)](https://circleci.com/gh/treydock/ssh_exporter)
[![GitHub release](https://img.shields.io/github/v/release/treydock/ssh_exporter?include_prereleases&sort=semver)](https://github.com/treydock/ssh_exporter/releases/latest)
![GitHub All Releases](https://img.shields.io/github/downloads/treydock/ssh_exporter/total)
![Docker Pulls](https://img.shields.io/docker/pulls/treydock/ssh_exporter)
[![Go Report Card](https://goreportcard.com/badge/github.com/treydock/ssh_exporter)](https://goreportcard.com/report/github.com/treydock/ssh_exporter)
[![codecov](https://codecov.io/gh/treydock/ssh_exporter/branch/master/graph/badge.svg)](https://codecov.io/gh/treydock/ssh_exporter)

# SSH exporter

The SSH exporter attempts to make an SSH connection to a remote system and optionally run a command and test output.

This expecter is intended to query multiple SSH servers from an external host.

The `/ssh` metrics endpoint exposes SSH metrics and requires the `target` parameter.
The `module` parameter can also be used to select which configuration module to use, the default module is `default`.

The `/metrics` endpoint exposes Go and process metrics for this exporter.

## Configuration

The configuration defines modules that are used to configure the SSH client for a given target.

Example:

```yaml
modules:
  default:
    user: prometheus
    private_key: /home/prometheus/.ssh/id_rsa
    command: uptime
    command_expect: "load average"
    timeout: 5
  password:
    id: prometheus
    password: secret
  verify:
    user: prometheus
    private_key: /home/prometheus/.ssh/id_rsa
    known_hosts: /etc/ssh/ssh_known_hosts
    host_key_algorithms:
    - ssh-rsa
    command: uptime
    command_expect: "load average"
    timeout: 5
```

Example with curl would query host1 with the password module and host2 with the default module.

```
curl http://localhost:9310/ssh?target=host1.example.com&module=password
curl http://localhost:9310/ssh?target=host2.example.com
```

Configuration options for each module:

* `user` - The username for the SSH connection
* `password` - The password for the SSH connection, required if `private_key` is not specified
* `private_key` - The SSH private key for the SSH connection, required if `password` is not specified
* `known_hosts` - Optional SSH known hosts file to use to verify hosts
* `host_key_algorithms` - Optional list of SSH host key algorithms to use
  * See constants beginning with `KeyAlgo*` in [crypto/ssh](https://godoc.org/golang.org/x/crypto/ssh#pkg-constants)
* `timeout` - Optional timeout of the SSH connection, session and optional command.
    * The default comes from the `--collector.ssh.default-timeout` flag.
* `command` - Optional command to run.
* `command_expect` - Optional regular expression of output to expect from the command.

## Docker

Example of running the Docker container

```
docker run -d -p 9312:9312 -v "ssh_exporter.yaml:/ssh_exporter.yaml:ro" treydock/ssh_exporter
```

Example of running the Docker container and making SSH private key available.
This requires setting `private_key` value to `/.ssh/id_rsa`.

```
docker run -d -p 9312:9312 \
-v "ssh_exporter.yaml:/ssh_exporter.yaml:ro" \
-v "/home/prometheus/.ssh/id_rsa:/.ssh/id_rsa:ro" \
treydock/ssh_exporter
```

## Install

Download the [latest release](https://github.com/treydock/ssh_exporter/releases)

Add the user that will run `ssh_exporter`

```
groupadd -r ssh_exporter
useradd -r -d /var/lib/ssh_exporter -s /sbin/nologin -M -g ssh_exporter -M ssh_exporter
```

Install compiled binaries after extracting tar.gz from release page.

```
cp /tmp/ssh_exporter /usr/local/bin/ssh_exporter
```

Add the necessary config, see [configuration section](#configuration)

Add systemd unit file and start service. Modify the `ExecStart` with desired flags.

```
cp systemd/ssh_exporter.service /etc/systemd/system/ssh_exporter.service
systemctl daemon-reload
systemctl start ssh_exporter
```

## Build from source

To produce the `ssh_exporter` binary:

```
make build
```

Or

```
go get github.com/treydock/ssh_exporter
```

## Prometheus configs

The following example assumes this exporter is running on the Prometheus server and communicating to the remote SSH hosts.

```yaml
- job_name: ssh
  metrics_path: /ssh
  static_configs:
  - targets:
    - host1.example.com:22
    - host2.example.com:22
    labels:
      module: default
  - targets:
    - host3.example.com:22
    - host4.example.com:22
    labels:
      module: verify
  relabel_configs:
  - source_labels: [__address__]
    target_label: __param_target
  - source_labels: [__param_target]
    target_label: instance
  - target_label: __address__
    replacement: 127.0.0.1:9312
  - source_labels: [module]
    target_label: __param_module
  metric_relabel_configs:
  - regex: "^(module)$"
    action: labeldrop
- job_name: ssh-metrics
  metrics_path: /metrics
  static_configs:
  - targets:
    - localhost:9312
```
