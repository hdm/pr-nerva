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

package fingerprinters

import (
	"net/http"
	"testing"
)

func TestRedisCommanderFingerprinter_Name(t *testing.T) {
	f := &RedisCommanderFingerprinter{}
	if name := f.Name(); name != "redis_commander" {
		t.Errorf("Name() = %q, expected %q", name, "redis_commander")
	}
}

func TestRedisCommanderFingerprinter_Match(t *testing.T) {
	f := &RedisCommanderFingerprinter{}

	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "matches text/html",
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "matches text/html with charset",
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "does not match application/json",
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "does not match empty content type",
			contentType: "",
			want:        false,
		},
		{
			name:        "does not match application/xml",
			contentType: "application/xml",
			want:        false,
		},
		{
			name:        "does not match text/plain",
			contentType: "text/plain",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: 200,
				Header:     http.Header{},
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			if got := f.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRedisCommanderFingerprinter_Fingerprint(t *testing.T) {
	f := &RedisCommanderFingerprinter{}

	tests := []struct {
		name         string
		statusCode   int
		contentType  string
		body         string
		wantResult   bool
		wantTech     string
		wantTitle    string
		wantReadOnly bool
		wantReadOnlySet bool // whether read_only is expected to be present in metadata
	}{
		{
			name:       "detects with title and redisCommander.js script",
			statusCode: 200,
			contentType: "text/html",
			body: `<!DOCTYPE html>
<html>
<head>
<title>Redis Commander: localhost</title>
<script src="/redisCommander.js"></script>
</head>
<body>
<div id="tree"></div>
</body>
</html>`,
			wantResult:      true,
			wantTech:        "redis_commander",
			wantTitle:       "localhost",
			wantReadOnly:    true,
			wantReadOnlySet: true,
		},
		{
			name:       "detects with title only (no script reference)",
			statusCode: 200,
			contentType: "text/html",
			body: `<!DOCTYPE html>
<html>
<head>
<title>Redis Commander: myserver</title>
</head>
<body>
</body>
</html>`,
			wantResult:      true,
			wantTech:        "redis_commander",
			wantTitle:       "myserver",
			wantReadOnly:    true,
			wantReadOnlySet: true,
		},
		{
			name:       "detects with redisCommander.js script only (no matching title)",
			statusCode: 200,
			contentType: "text/html",
			body: `<!DOCTYPE html>
<html>
<head>
<title>My App</title>
<script src="/redisCommander.js"></script>
</head>
<body>
</body>
</html>`,
			wantResult: true,
			wantTech:   "redis_commander",
		},
		{
			name:       "detects editing modals present means read_only false",
			statusCode: 200,
			contentType: "text/html",
			body: `<!DOCTYPE html>
<html>
<head>
<title>Redis Commander: localhost</title>
</head>
<body>
<div id="addListValue">
<input type="text" name="value">
</div>
</body>
</html>`,
			wantResult:      true,
			wantTech:        "redis_commander",
			wantTitle:       "localhost",
			wantReadOnly:    false,
			wantReadOnlySet: true,
		},
		{
			name:       "no editing modals means read_only true",
			statusCode: 200,
			contentType: "text/html",
			body: `<!DOCTYPE html>
<html>
<head>
<title>Redis Commander: localhost</title>
</head>
<body>
<div id="tree"></div>
</body>
</html>`,
			wantResult:      true,
			wantTech:        "redis_commander",
			wantTitle:       "localhost",
			wantReadOnly:    true,
			wantReadOnlySet: true,
		},
		{
			name:       "custom title extraction with port in title",
			statusCode: 200,
			contentType: "text/html",
			body: `<!DOCTYPE html>
<html>
<head>
<title>Redis Commander: myredis:6379</title>
</head>
<body>
</body>
</html>`,
			wantResult: true,
			wantTech:   "redis_commander",
			wantTitle:  "myredis:6379",
		},
		{
			name:       "returns nil for HTML without any Redis Commander markers",
			statusCode: 200,
			contentType: "text/html",
			body: `<!DOCTYPE html>
<html>
<head>
<title>Some Other App</title>
</head>
<body>
<p>Welcome to some other app</p>
</body>
</html>`,
			wantResult: false,
		},
		{
			name:       "returns nil for random HTML page",
			statusCode: 200,
			contentType: "text/html",
			body: `<html><head><title>My Page</title></head><body><p>Hello world</p></body></html>`,
			wantResult: false,
		},
		{
			name:        "returns nil for empty body",
			statusCode:  200,
			contentType: "text/html",
			body:        "",
			wantResult:  false,
		},
		{
			name:       "returns nil for non-HTML JSON content",
			statusCode: 200,
			contentType: "application/json",
			body:        `{"status": "ok"}`,
			wantResult:  false,
		},
		{
			name:       "case-insensitive title detection",
			statusCode: 200,
			contentType: "text/html",
			body: `<!DOCTYPE html>
<html>
<head>
<title>redis commander: localhost</title>
</head>
<body></body>
</html>`,
			wantResult: true,
			wantTech:   "redis_commander",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     http.Header{},
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}

			result, err := f.Fingerprint(resp, []byte(tt.body))

			if err != nil {
				t.Errorf("Fingerprint() error = %v", err)
				return
			}

			if tt.wantResult && result == nil {
				t.Error("Fingerprint() returned nil, expected result")
				return
			}

			if !tt.wantResult && result != nil {
				t.Errorf("Fingerprint() returned result, expected nil")
				return
			}

			if result == nil {
				return
			}

			if result.Technology != tt.wantTech {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
			}

			if result.Version != "" {
				t.Errorf("Version = %q, expected empty (Redis Commander does not expose version)", result.Version)
			}

			if len(result.CPEs) == 0 {
				t.Error("CPEs should not be empty")
			} else {
				expectedCPE := "cpe:2.3:a:redis-commander:redis_commander:*:*:*:*:*:*:*:*"
				if result.CPEs[0] != expectedCPE {
					t.Errorf("CPEs[0] = %q, want %q", result.CPEs[0], expectedCPE)
				}
			}

			if tt.wantTitle != "" {
				title, ok := result.Metadata["title"]
				if !ok {
					t.Error("Metadata missing 'title' key")
				} else if title != tt.wantTitle {
					t.Errorf("Metadata[title] = %q, want %q", title, tt.wantTitle)
				}
			}

			if tt.wantReadOnlySet {
				readOnly, ok := result.Metadata["read_only"]
				if !ok {
					t.Error("Metadata missing 'read_only' key")
				} else if readOnly != tt.wantReadOnly {
					t.Errorf("Metadata[read_only] = %v, want %v", readOnly, tt.wantReadOnly)
				}
			}
		})
	}
}

func TestBuildRedisCommanderCPE(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "wildcard version",
			want: "cpe:2.3:a:redis-commander:redis_commander:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildRedisCommanderCPE(); got != tt.want {
				t.Errorf("buildRedisCommanderCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}
