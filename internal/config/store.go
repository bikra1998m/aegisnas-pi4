package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"
)

func SettingsSnapshot() map[string]any {
	globalConfigMu.RLock()
	defer globalConfigMu.RUnlock()
	return settingsSnapshotLocked()
}

func settingsSnapshotLocked() map[string]any {
	if globalConfig == nil {
		return map[string]any{}
	}
	value := taggedValue(reflect.ValueOf(*globalConfig))
	if snapshot, ok := value.(map[string]any); ok {
		return snapshot
	}
	return map[string]any{}
}

func SaveSettingsMap(input map[string]any) (*Config, error) {
	if input == nil {
		return nil, fmt.Errorf("settings payload cannot be empty")
	}

	next, err := decodeSettingsMap(input)
	if err != nil {
		return nil, err
	}
	if err := next.Validate(); err != nil {
		return nil, err
	}
	globalConfigMu.RLock()
	identityChanged := globalConfig != nil && !sameVendorIdentitySettings(globalConfig.Radius.Vendor, next.Radius.Vendor)
	globalConfigMu.RUnlock()
	if identityChanged {
		return nil, fmt.Errorf("radius.vendor identity fields can only be changed through the verified vendor identity migration workflow")
	}
	globalConfigMu.Lock()
	defer globalConfigMu.Unlock()
	if err := saveToDiskLocked(next); err != nil {
		return nil, err
	}
	globalConfig = next
	return globalConfig, nil
}

type vendorIdentitySettings struct {
	Name                     string
	ID                       int
	IdentityMode             string
	AssignedOrganization     string
	AssignmentRegistryURL    string
	RegistryLastUpdated      string
	AssignmentVerifiedAt     string
	AssignmentRegistrySHA256 string
	AssignmentRecordSHA256   string
	LegacyIDs                []int
	LegacyAcceptUntil        string
}

func sameVendorIdentitySettings(left, right RadiusVendorConfig) bool {
	toSettings := func(v RadiusVendorConfig) vendorIdentitySettings {
		return vendorIdentitySettings{
			Name: v.Name, ID: v.ID, IdentityMode: v.IdentityMode,
			AssignedOrganization: v.AssignedOrganization, AssignmentRegistryURL: v.AssignmentRegistryURL,
			RegistryLastUpdated: v.RegistryLastUpdated, AssignmentVerifiedAt: v.AssignmentVerifiedAt,
			AssignmentRegistrySHA256: v.AssignmentRegistrySHA, AssignmentRecordSHA256: v.AssignmentRecordSHA,
			LegacyIDs: append([]int(nil), v.LegacyIDs...), LegacyAcceptUntil: v.LegacyAcceptUntil,
		}
	}
	return reflect.DeepEqual(toSettings(left), toSettings(right))
}

func WriteFile(path string, cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}
	target := strings.TrimSpace(path)
	if target == "" {
		target = "config.yaml"
	}
	payload := taggedValue(reflect.ValueOf(*cfg))
	data, err := yaml.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	dir := filepath.Dir(target)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
	}
	return atomicWriteFile(target, data, 0640)
}

func atomicWriteFile(target string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(target)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".aegisnas-config-*")
	if err != nil {
		return fmt.Errorf("create temporary config file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("set temporary config permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temporary config file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temporary config file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary config file: %w", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("replace config file atomically: %w", err)
	}
	return nil
}

func EvaluateSettingsMap(input map[string]any) (*Config, error) {
	if input == nil {
		return nil, fmt.Errorf("settings payload cannot be empty")
	}
	return decodeSettingsMap(input)
}

func SaveConfig(cfg *Config) (*Config, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	globalConfigMu.Lock()
	defer globalConfigMu.Unlock()
	if err := saveToDiskLocked(cfg); err != nil {
		return nil, err
	}
	copy := *cfg
	globalConfig = &copy
	return globalConfig, nil
}

func saveToDisk(cfg *Config) error {
	globalConfigMu.RLock()
	defer globalConfigMu.RUnlock()
	return saveToDiskLocked(cfg)
}

func saveToDiskLocked(cfg *Config) error {
	target := strings.TrimSpace(globalConfigPath)
	if target == "" {
		target = "config.yaml"
	}
	return WriteFile(target, cfg)
}

func mergeMaps(dst, src map[string]any) {
	for key, value := range src {
		srcMap, srcIsMap := value.(map[string]any)
		dstMap, dstIsMap := dst[key].(map[string]any)
		if srcIsMap && dstIsMap {
			mergeMaps(dstMap, srcMap)
			continue
		}
		dst[key] = value
	}
}

func decodeSettingsMap(input map[string]any) (*Config, error) {
	base := SettingsSnapshot()
	mergeMaps(base, input)

	var next Config
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName:          "mapstructure",
		WeaklyTypedInput: true,
		Result:           &next,
	})
	if err != nil {
		return nil, err
	}
	if err := decoder.Decode(base); err != nil {
		return nil, fmt.Errorf("decode settings: %w", err)
	}
	return &next, nil
}

func taggedValue(value reflect.Value) any {
	if !value.IsValid() {
		return nil
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		return taggedValue(value.Elem())
	}

	switch value.Kind() {
	case reflect.Struct:
		out := make(map[string]any)
		valueType := value.Type()
		for i := 0; i < value.NumField(); i++ {
			field := valueType.Field(i)
			if field.PkgPath != "" {
				continue
			}
			tag := field.Tag.Get("mapstructure")
			if tag == "" || tag == "-" {
				continue
			}
			out[tag] = taggedValue(value.Field(i))
		}
		return out
	case reflect.Slice, reflect.Array:
		items := make([]any, 0, value.Len())
		for i := 0; i < value.Len(); i++ {
			items = append(items, taggedValue(value.Index(i)))
		}
		return items
	case reflect.Map:
		iter := value.MapRange()
		out := make(map[string]any)
		for iter.Next() {
			out[fmt.Sprint(iter.Key().Interface())] = taggedValue(iter.Value())
		}
		return out
	default:
		return value.Interface()
	}
}
