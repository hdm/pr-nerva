// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package qdrant

import (
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestExtractVersionFromString(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantVersion string
	}{
		{
			name:        "standard version",
			body:        `{"title":"qdrant","version":"1.7.4"}`,
			wantVersion: "1.7.4",
		},
		{
			name:        "version with v prefix",
			body:        `{"title":"qdrant","version":"v1.7.4"}`,
			wantVersion: "1.7.4",
		},
		{
			name:        "version with pre-release",
			body:        `{"title":"qdrant","version":"1.7.4-beta"}`,
			wantVersion: "1.7.4-beta",
		},
		{
			name:        "no version",
			body:        `{"title":"qdrant"}`,
			wantVersion: "",
		},
		{
			name:        "empty body",
			body:        "",
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractVersionFromString(tt.body)
			if result != tt.wantVersion {
				t.Errorf("extractVersionFromString() = %q, want %q", result, tt.wantVersion)
			}
		})
	}
}

func TestBuildQdrantCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantCPE string
	}{
		{
			name:    "standard version",
			version: "1.7.4",
			wantCPE: "cpe:2.3:a:qdrant:qdrant:1.7.4:*:*:*:*:*:*:*",
		},
		{
			name:    "unknown version",
			version: "",
			wantCPE: "cpe:2.3:a:qdrant:qdrant:*:*:*:*:*:*:*:*",
		},
		{
			name:    "version with pre-release",
			version: "1.7.4-beta",
			wantCPE: "cpe:2.3:a:qdrant:qdrant:1.7.4-beta:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildQdrantCPE(tt.version)
			if result != tt.wantCPE {
				t.Errorf("buildQdrantCPE() = %q, want %q", result, tt.wantCPE)
			}
		})
	}
}

func TestQdrantPluginInterface(t *testing.T) {
	plugin := &QdrantPlugin{}

	t.Run("Name", func(t *testing.T) {
		if name := plugin.Name(); name != QDRANT {
			t.Errorf("Name() = %q, want %q", name, QDRANT)
		}
	})

	t.Run("Type", func(t *testing.T) {
		if pluginType := plugin.Type(); pluginType != plugins.TCP {
			t.Errorf("Type() = %v, want TCP", pluginType)
		}
	})

	t.Run("Priority", func(t *testing.T) {
		if priority := plugin.Priority(); priority != 50 {
			t.Errorf("Priority() = %d, want 50", priority)
		}
	})

	t.Run("PortPriority default port 6333", func(t *testing.T) {
		if !plugin.PortPriority(6333) {
			t.Error("PortPriority(6333) = false, want true")
		}
	})

	t.Run("PortPriority non-default port", func(t *testing.T) {
		if plugin.PortPriority(8080) {
			t.Error("PortPriority(8080) = true, want false")
		}
	})
}
