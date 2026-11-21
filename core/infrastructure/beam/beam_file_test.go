package beam

import (
	"testing"
)

func TestBeamFile_AddNode(t *testing.T) {
	bf := New("Test", "Provider", "")

	bf.AddNode("node1", "cat1", "Server 1", "vless", map[string]interface{}{
		"server": "example.com",
	})

	if len(bf.Data.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(bf.Data.Nodes))
	}

	if bf.Data.SelectedID != "node1" {
		t.Fatalf("expected selectedID=node1, got %s", bf.Data.SelectedID)
	}
}

func TestBeamFile_SetSelected(t *testing.T) {
	bf := New("Test", "Provider", "")
	bf.AddNode("node1", "cat1", "Server 1", "vless", map[string]interface{}{})
	bf.AddNode("node2", "cat1", "Server 2", "vmess", map[string]interface{}{})

	if !bf.SetSelected("node2") {
		t.Fatal("SetSelected must return true for an existing node")
	}

	if bf.Data.SelectedID != "node2" {
		t.Fatalf("expected selectedID=node2, got %s", bf.Data.SelectedID)
	}

	if bf.SetSelected("non_existent") {
		t.Fatal("SetSelected must return false for a missing node")
	}
}

func TestBeamFile_GetNodesGrouped(t *testing.T) {
	bf := New("Test", "Provider", "")
	bf.AddCategory("cat1", "Gaming", "Gamepad2", 0)
	bf.AddCategory("cat2", "Streaming", "Play", 1)

	bf.AddNode("n1", "cat1", "Gaming 1", "vless", map[string]interface{}{})
	bf.AddNode("n2", "cat1", "Gaming 2", "vless", map[string]interface{}{})
	bf.AddNode("n3", "cat2", "Stream 1", "vmess", map[string]interface{}{})

	grouped := bf.GetNodesGrouped()

	if len(grouped) != 2 {
		t.Fatalf("expected 2 categories, got %d", len(grouped))
	}

	if len(grouped[0].Nodes) != 2 {
		t.Fatalf("category 1 should have 2 nodes, got %d", len(grouped[0].Nodes))
	}

	if !grouped[0].Nodes[0].IsSelected {
		t.Fatal("the first node must be selected")
	}
}

func TestBeamFile_Validate(t *testing.T) {
	bf := New("", "Provider", "")
	if err := bf.Validate(); err == nil {
		t.Fatal("Validate must return an error for an empty name")
	}

	bf.Data.Name = "Test"
	if err := bf.Validate(); err == nil {
		t.Fatal("Validate must return an error for a profile without nodes")
	}

	bf.AddNode("n1", "cat1", "Server", "vless", map[string]interface{}{})
	if err := bf.Validate(); err != nil {
		t.Fatalf("Validate must not return an error: %v", err)
	}
}
