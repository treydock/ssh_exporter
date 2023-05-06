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

package config

import (
	"fmt"
	"os"
	"sync"

	"github.com/alecthomas/kingpin/v2"
	yaml "gopkg.in/yaml.v3"
)

var (
	defaultTimeout        = kingpin.Flag("collector.ssh.default-timeout", "Default timeout for SSH collection").Default("10").Int()
	defaultOutputTruncate = kingpin.Flag("collector.ssh.default-output-truncate",
		"Default output truncate length when output metric is enabled").Default("50").Int()
)

type Config struct {
	Modules map[string]*Module `yaml:"modules"`
}

type SafeConfig struct {
	sync.RWMutex
	C *Config
}

type Module struct {
	ModuleName        string
	User              string   `yaml:"user"`
	Password          string   `yaml:"password"`
	PrivateKey        string   `yaml:"private_key"`
	Certificate       string   `yaml:"certificate"`
	KnownHosts        string   `yaml:"known_hosts"`
	HostKeyAlgorithms []string `yaml:"host_key_algorithms"`
	Timeout           int      `yaml:"timeout"`
	Command           string   `yaml:"command"`
	CommandExpect     string   `yaml:"command_expect"`
	OutputMetric      bool     `yaml:"output_metric"`
	OutputTruncate    int      `yaml:"output_truncate"`
}

type Target struct {
	Host              string
	User              string
	Password          string
	PrivateKey        string
	Certificate       string
	KnownHosts        string
	HostKeyAlgorithms []string
	Timeout           int
	Command           string
	CommandExpect     string
	OutputMetric      bool
	OutputTruncate    int
}

func (sc *SafeConfig) ReloadConfig(configFile string) error {
	var c = &Config{}
	yamlReader, err := os.Open(configFile)
	if err != nil {
		return fmt.Errorf("Error reading config file %s: %s", configFile, err)
	}
	defer yamlReader.Close()
	decoder := yaml.NewDecoder(yamlReader)
	decoder.KnownFields(true)
	if err := decoder.Decode(c); err != nil {
		return fmt.Errorf("Error parsing config file %s: %s", configFile, err)
	}
	for key := range c.Modules {
		module := c.Modules[key]
		module.ModuleName = key
		if module.User == "" {
			return fmt.Errorf("Module %s must define 'user' value", key)
		}
		if module.Password == "" && module.PrivateKey == "" {
			return fmt.Errorf("Module %s must define 'password' or 'private_key' value", key)
		}
		if module.Certificate != "" && module.PrivateKey == "" {
			return fmt.Errorf("Module %s must define 'private_key' if it defines a 'certificate' value", key)
		}
		if module.Timeout == 0 {
			module.Timeout = *defaultTimeout
		}
		if module.OutputTruncate == 0 {
			module.OutputTruncate = *defaultOutputTruncate
		}
		c.Modules[key] = module
	}
	sc.Lock()
	sc.C = c
	sc.Unlock()
	return nil
}
