package beam

import (
	"encoding/json"
	"fmt"
	"time"

	"beam-bridge/core/types"
)

func migrateFromV1(content []byte) (*BeamFile, error) {
	var legacy types.LegacyBeamFileData
	if err := json.Unmarshal(content, &legacy); err != nil {
		return nil, err
	}

	beam := &BeamFile{
		Data: types.BeamFileData{
			Version:    CurrentVersion,
			Categories: []types.Category{},
			Nodes:      []types.BeamNode{},
			ExpiresAt:  legacy.ExpiresAt,
			DataLimit:  legacy.DataLimit,
			CreatedAt:  time.Now().Unix(),
			UpdatedAt:  time.Now().Unix(),
		},
	}

	if legacy.Profile != nil {
		beam.Data.Name = legacy.Profile.Name
		beam.Data.Provider = legacy.Profile.Provider
		beam.Data.URL = legacy.Profile.URL
	}

	if legacy.Config != nil {
		if err := migrateConfig(beam, legacy.Config); err != nil {
			return nil, err
		}
	}

	return beam, nil
}

func migrateConfig(beam *BeamFile, config interface{}) error {
	configMap, ok := config.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid config format")
	}

	outbounds, ok := configMap["outbounds"].([]interface{})
	if !ok {
		return fmt.Errorf("missing outbounds")
	}

	beam.AddCategory("default", "Серверы", "Folder", 0)

	nodeIndex := 0
	for _, ob := range outbounds {
		obMap, ok := ob.(map[string]interface{})
		if !ok {
			continue
		}

		obType, _ := obMap["type"].(string)
		if isServiceOutbound(obType) {
			continue
		}

		tag, _ := obMap["tag"].(string)
		if tag == "" {
			continue
		}

		nodeID := fmt.Sprintf("node_%d", nodeIndex)
		beam.AddNode(nodeID, "default", tag, obType, obMap)
		nodeIndex++
	}

	return nil
}

func isServiceOutbound(obType string) bool {
	serviceTypes := map[string]bool{
		"selector": true,
		"direct":   true,
		"block":    true,
		"dns":      true,
		"urltest":  true,
	}
	return serviceTypes[obType]
}
