package main

import (
	"encoding/json"
	"os"
)

// Load networks from JSON file
func loadNetworks(filename string) ([]Network, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var networks []Network
	err = json.Unmarshal(data, &networks)
	if err != nil {
		return nil, err
	}

	return networks, nil
}
