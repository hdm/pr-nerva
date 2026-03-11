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

package teamviewer

import (
	"bytes"
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
)

func TestCheckTeamViewer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid CMD_PINGOK response",
			data:    []byte{0x17, 0x24, 0x11, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "valid secondary magic",
			data:    []byte{0x11, 0x30, 0x11, 0x04, 0x00},
			wantErr: false,
		},
		{
			name:    "valid primary magic with different command",
			data:    []byte{0x17, 0x24, 0x16, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "minimum valid response (3 bytes)",
			data:    []byte{0x17, 0x24, 0x11},
			wantErr: false,
		},
		{
			name:    "invalid magic bytes",
			data:    []byte{0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "response too short (2 bytes)",
			data:    []byte{0x17, 0x24},
			wantErr: true,
		},
		{
			name:    "response too short (1 byte)",
			data:    []byte{0x17},
			wantErr: true,
		},
		{
			name:    "empty response",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "HTTP response (not TeamViewer)",
			data:    []byte("HTTP/1.1 200 OK"),
			wantErr: true,
		},
		{
			name:    "partial magic match (first byte only)",
			data:    []byte{0x17, 0x00, 0x11},
			wantErr: true,
		},
		{
			name:    "nil input",
			data:    nil,
			wantErr: true,
		},
		{
			name:    "large response starting with valid magic bytes",
			data:    append([]byte{0x17, 0x24, 0x11}, bytes.Repeat([]byte{0xAB}, 64*1024-3)...),
			wantErr: false,
		},
		{
			name:    "all 0xFF bytes",
			data:    []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			wantErr: true,
		},
		{
			name:    "magic bytes reversed",
			data:    []byte{0x24, 0x17, 0x11},
			wantErr: true,
		},
		{
			name:    "secondary magic with minimum bytes",
			data:    []byte{0x11, 0x30, 0x10},
			wantErr: false,
		},
		{
			name:    "binary data after valid magic",
			data:    []byte{0x17, 0x24, 0x10, 0xFF, 0xFF, 0xFF, 0xFF},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := checkTeamViewer(tt.data)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCmdPingProbe(t *testing.T) {
	// Verify probe is exactly 9 bytes
	assert.Equal(t, 9, len(cmdPingProbe))
	// Verify magic bytes
	assert.Equal(t, byte(0x17), cmdPingProbe[0])
	assert.Equal(t, byte(0x24), cmdPingProbe[1])
	// Verify CMD_PING command
	assert.Equal(t, byte(0x10), cmdPingProbe[2])
}

func TestPluginMetadata(t *testing.T) {
	p := &TeamViewerPlugin{}
	assert.Equal(t, "TeamViewer", p.Name())
	assert.Equal(t, plugins.TCP, p.Type())
	assert.Equal(t, 100, p.Priority())
	assert.True(t, p.PortPriority(5938))
	assert.False(t, p.PortPriority(80))
	assert.False(t, p.PortPriority(443))
	assert.False(t, p.PortPriority(5900))
}
