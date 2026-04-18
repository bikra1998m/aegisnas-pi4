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
	if err := next.Validate(); err != nil {
		return nil, err
	}
	if err := saveToDisk(&next); err != nil {
		return nil, err
	}
	globalConfig = &next
	return globalConfig, nil
}

func saveToDisk(cfg *Config) error {
	target := strings.TrimSpace(globalConfigPath)
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
	if err := os.WriteFile(target, data, 0640); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}
	return nil
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
