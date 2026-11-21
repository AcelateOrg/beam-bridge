package beam

import (
	"fmt"
	"time"

	"beam-bridge/core/types"
)

type BeamFile struct {
	Data types.BeamFileData
}

func New(name, provider, url string) *BeamFile {
	now := time.Now().Unix()
	return &BeamFile{
		Data: types.BeamFileData{
			Version:    CurrentVersion,
			Name:       name,
			Provider:   provider,
			URL:        url,
			Categories: []types.Category{},
			Nodes:      []types.BeamNode{},
			CreatedAt:  now,
			UpdatedAt:  now,
		},
	}
}

func (bf *BeamFile) AddCategory(id, name, icon string, order int) {
	bf.Data.Categories = append(bf.Data.Categories, types.Category{
		ID:    id,
		Name:  name,
		Icon:  icon,
		Order: order,
	})
}

func (bf *BeamFile) AddNode(id, categoryID, name, nodeType string, outbound map[string]interface{}) {
	bf.Data.Nodes = append(bf.Data.Nodes, types.BeamNode{
		ID:         id,
		CategoryID: categoryID,
		Name:       name,
		Type:       nodeType,
		Outbound:   outbound,
	})
	if bf.Data.SelectedID == "" {
		bf.Data.SelectedID = id
	}
}

func (bf *BeamFile) SetSelected(nodeID string) bool {
	for _, node := range bf.Data.Nodes {
		if node.ID == nodeID {
			bf.Data.SelectedID = nodeID
			bf.Data.UpdatedAt = time.Now().Unix()
			return true
		}
	}
	return false
}

func (bf *BeamFile) GetSelectedNode() *types.BeamNode {
	for i := range bf.Data.Nodes {
		if bf.Data.Nodes[i].ID == bf.Data.SelectedID {
			return &bf.Data.Nodes[i]
		}
	}
	if len(bf.Data.Nodes) > 0 {
		return &bf.Data.Nodes[0]
	}
	return nil
}

func (bf *BeamFile) GetNodesGrouped() []types.CategoryWithNodes {
	categoryMap := make(map[string]*types.CategoryWithNodes)
	categoryOrder := make([]string, 0)
	for _, cat := range bf.Data.Categories {
		categoryMap[cat.ID] = &types.CategoryWithNodes{
			Category: cat,
			Nodes:    []types.NodeInfo{},
		}
		categoryOrder = append(categoryOrder, cat.ID)
	}

	defaultCatID := "__default__"
	hasUncategorized := false
	for i := range bf.Data.Nodes {
		node := &bf.Data.Nodes[i]
		catID := node.CategoryID
		if catID == "" {
			catID = defaultCatID
			hasUncategorized = true
		}
		if _, ok := categoryMap[catID]; !ok {
			categoryMap[catID] = &types.CategoryWithNodes{
				Category: types.Category{
					ID:    catID,
					Name:  "Серверы",
					Order: 999,
				},
				Nodes: []types.NodeInfo{},
			}
			if catID == defaultCatID {
				categoryOrder = append(categoryOrder, catID)
			}
		}
		effective := node.EffectiveOutbound()
		transport, security := types.DescribeOutbound(effective)
		categoryMap[catID].Nodes = append(categoryMap[catID].Nodes, types.NodeInfo{
			ID:         node.ID,
			Name:       node.DisplayName(),
			Type:       node.Type,
			CategoryID: node.CategoryID,
			IsSelected: node.ID == bf.Data.SelectedID,
			IsEdited:   node.IsEdited(),
			IsPinned:   node.IsPinned(),
			Transport:  transport,
			Security:   security,
			Insecure:   types.InsecureOutbound(effective),
			Description:  node.Description,
			Badge:        node.Badge,
			HideProtocol: bf.Data.NodeSubtitle == types.NodeSubtitleNone,
		})
	}

	result := make([]types.CategoryWithNodes, 0)
	for _, catID := range categoryOrder {
		if cat, ok := categoryMap[catID]; ok && len(cat.Nodes) > 0 {
			result = append(result, *cat)
		}
	}
	if hasUncategorized {
		if cat, ok := categoryMap[defaultCatID]; ok && len(cat.Nodes) > 0 {
			result = append(result, *cat)
		}
	}
	return result
}

func (bf *BeamFile) Validate() error {
	if bf.Data.Name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if len(bf.Data.Nodes) == 0 {
		return fmt.Errorf("profile must contain at least one node")
	}
	if bf.Data.SelectedID != "" {
		found := false
		for _, node := range bf.Data.Nodes {
			if node.ID == bf.Data.SelectedID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("selected node %s not found", bf.Data.SelectedID)
		}
	}
	return nil
}
