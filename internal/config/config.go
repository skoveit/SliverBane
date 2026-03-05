package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Profile struct {
	Name      string `json:"name"`
	CertPath  string `json:"cert_path"`
	KeyPath   string `json:"key_path"`
	AgeKey    string `json:"age_key"`
	TargetURL string `json:"target_url"`
}

type Config struct {
	ActiveProfile string             `json:"active"`
	Profiles      map[string]Profile `json:"profiles"`
}

func GetConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".sliverbane")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

func LoadConfig() (*Config, error) {
	path, err := GetConfigPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Config{Profiles: make(map[string]Profile)}, nil
	} else if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Profiles == nil {
		cfg.Profiles = make(map[string]Profile)
	}
	return &cfg, nil
}

func SaveConfig(cfg *Config) error {
	path, err := GetConfigPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

func GetActiveProfile() (*Profile, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, err
	}
	if cfg.ActiveProfile == "" {
		return nil, fmt.Errorf("no active profile set")
	}
	p, ok := cfg.Profiles[cfg.ActiveProfile]
	if !ok {
		return nil, fmt.Errorf("active profile '%s' not found", cfg.ActiveProfile)
	}
	return &p, nil
}
