package subscription

import (
	"errors"
	"strings"

	"beam-bridge/core/infrastructure/beam"
)

// maxInlineLinks bounds the links of one document: a beam:// link is a
// handful of servers, not a dump.
const maxInlineLinks = 1000

// ExpandLinks turns the short form of a generated profile (BeamFileData.Links:
// share links and group markers, as in a plain subscription) into nodes. Nodes
// the document already has stay first; Links is cleared afterwards.
func (a *Aggregator) ExpandLinks(bf *beam.BeamFile) error {
	if bf == nil || len(bf.Data.Links) == 0 {
		return nil
	}
	links := bf.Data.Links
	bf.Data.Links = nil
	if len(links) > maxInlineLinks {
		return errors.New("too many links in the profile")
	}

	clean := make([]string, 0, len(links))
	for _, link := range links {
		// One entry is one line: a link cannot smuggle a second one in.
		link = strings.TrimSpace(strings.NewReplacer("\r", "", "\n", "").Replace(link))
		if link != "" {
			clean = append(clean, link)
		}
	}
	result, err := a.ParseSubscription([]byte(strings.Join(clean, "\n")))
	if err != nil {
		if len(bf.Data.Nodes) > 0 {
			return nil
		}
		return errors.New("no supported server links in the profile")
	}

	if len(bf.Data.Nodes) == 0 && len(bf.Data.Categories) == 0 {
		bf.Data.Categories = result.Categories
		bf.Data.Nodes = result.Nodes
	} else {
		// Keep the ids of the document's own nodes and groups unique.
		categoryIDs := make(map[string]string, len(result.Categories))
		order := len(bf.Data.Categories)
		for _, category := range result.Categories {
			id := "link_" + category.ID
			categoryIDs[category.ID] = id
			category.ID = id
			category.Order = order
			order++
			bf.Data.Categories = append(bf.Data.Categories, category)
		}
		for _, node := range result.Nodes {
			node.ID = "link_" + node.ID
			node.CategoryID = categoryIDs[node.CategoryID]
			bf.Data.Nodes = append(bf.Data.Nodes, node)
		}
	}
	if bf.Data.SelectedID == "" && len(bf.Data.Nodes) > 0 {
		bf.Data.SelectedID = bf.Data.Nodes[0].ID
	}
	return nil
}
