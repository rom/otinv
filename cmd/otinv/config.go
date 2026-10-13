package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"gopkg.in/yaml.v3"
)

// DefaultConfigPath is where otinv looks for its configuration when no
// --config flag is given.
const DefaultConfigPath = "otinv.yaml"

// Config is the on-disk configuration. See otinv.example.yaml.
//
// Nothing here can make otinv active: the only protocol knobs are which ports
// to consider and how sure a heuristic has to be.
type Config struct {
	Protocols map[string]ProtocolConfig `yaml:"protocols"`
	Probe     ProbeConfig               `yaml:"probe"`
}

// ProtocolConfig holds per-protocol settings.
type ProtocolConfig struct {
	ExtraPorts []uint16 `yaml:"extra_ports"`
}

// ProbeConfig tunes heuristic protocol detection.
type ProbeConfig struct {
	MinConfidence int `yaml:"min_confidence"`
}

// LoadConfig reads the configuration file. A missing file at the default path
// is not an error; a missing file the user asked for is.
func LoadConfig(path string) (*Config, error) {
	explicit := path != ""
	if !explicit {
		path = DefaultConfigPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if !explicit && errors.Is(err, fs.ErrNotExist) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	if cfg.Probe.MinConfidence < 0 || cfg.Probe.MinConfidence > 100 {
		return nil, fmt.Errorf("config %s: probe.min_confidence must be between 0 and 100", path)
	}
	return &cfg, nil
}

// ExtraTCPPorts converts the config into the form ingest expects.
func (c *Config) ExtraTCPPorts() map[string][]uint16 {
	if len(c.Protocols) == 0 {
		return nil
	}
	out := make(map[string][]uint16, len(c.Protocols))
	for name, p := range c.Protocols {
		if len(p.ExtraPorts) > 0 {
			out[name] = p.ExtraPorts
		}
	}
	return out
}
