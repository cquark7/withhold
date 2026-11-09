package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// TOML renders the effective public configuration as a reloadable snapshot.
func TOML(c Config) ([]byte, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var values map[string]any
	if err := decoder.Decode(&values); err != nil {
		return nil, err
	}
	value, err := tomlNumbers(values)
	if err != nil {
		return nil, err
	}
	return toml.Marshal(value)
}

// JSON's number representation must be converted before TOML encoding; in
// particular, integer fields must not be emitted as TOML floats.
func tomlNumbers(value any) (any, error) {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			converted, err := tomlNumbers(item)
			if err != nil {
				return nil, err
			}
			v[key] = converted
		}
	case []any:
		for i, item := range v {
			converted, err := tomlNumbers(item)
			if err != nil {
				return nil, err
			}
			v[i] = converted
		}
	case json.Number:
		if !strings.ContainsAny(string(v), ".eE") {
			return strconv.ParseInt(string(v), 10, 64)
		}
		return strconv.ParseFloat(string(v), 64)
	case nil:
		return nil, errors.New("effective configuration contains an unsupported null")
	}
	return value, nil
}
