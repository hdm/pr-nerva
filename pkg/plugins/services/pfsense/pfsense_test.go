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

package pfsense

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testTimeout = 5 * time.Second

// mockConn writes a canned response to a net.Pipe connection.
// The caller receives the client-side conn; this goroutine drains the incoming
// request and then writes the canned response, then closes the server side.
func mockConn(t *testing.T, response []byte) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		// Drain the incoming request before writing the response.
		// net.Pipe is synchronous; writing blocks until the other side reads.
		buf := make([]byte, 4096)
		server.SetDeadline(time.Now().Add(testTimeout)) //nolint:errcheck
		server.Read(buf)                                //nolint:errcheck
		server.Write(response)                          //nolint:errcheck
	}()
	return client
}

// --- Response builders ---

func buildPfSenseLoginPage(serverHeader string, titlePrefix string, extraBody string) []byte {
	title := "pfSense - Login"
	if titlePrefix != "" {
		title = titlePrefix + " - Login"
	}

	headers := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n"
	if serverHeader != "" {
		headers += "Server: " + serverHeader + "\r\n"
	}
	headers += "\r\n"

	body := `<!DOCTYPE html>
<html>
<head><title>` + title + `</title></head>
<body>
<div class="loginCont">
  <span id="pfsense-logo-svg"><svg><!-- logo --></svg></span>
  <form>
    <input type="text" name="usernamefld" />
    <input type="password" name="passwordfld" />
    <input type="submit" value="Sign In" />
  </form>
</div>
` + extraBody + `
</body>
</html>`

	return []byte(headers + body)
}

func buildNonPfSensePage() []byte {
	return []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
		`<html><body><form><input name="username"/><input name="password"/></form></body></html>`)
}

func buildEmptyResponse() []byte {
	return []byte{}
}

func buildNonHTTPResponse() []byte {
	return []byte("SSH-2.0-OpenSSH_8.4p1\r\n")
}

// --- Tests ---

// TestDetectPfSense_AllMarkers verifies detection when all markers are present.
func TestDetectPfSense_AllMarkers(t *testing.T) {
	conn := mockConn(t, buildPfSenseLoginPage("", "", ""))
	defer conn.Close()

	payload, detected, err := detectPfSense(conn, testTimeout)
	require.NoError(t, err)
	assert.True(t, detected, "should detect pfSense with all markers present")
	require.NotNil(t, payload)
	assert.NotEmpty(t, payload.CPEs, "CPEs should be populated")
	assert.Equal(t, "cpe:2.3:a:netgate:pfsense:*:*:*:*:*:*:*:*", payload.CPEs[0])
}

// TestDetectPfSense_PrimaryOnly verifies detection when only username/password fields are present.
func TestDetectPfSense_PrimaryOnly(t *testing.T) {
	body := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
		`<html><body><form>` +
		`<input name="usernamefld"/>` +
		`<input name="passwordfld"/>` +
		`</form></body></html>`

	conn := mockConn(t, []byte(body))
	defer conn.Close()

	payload, detected, err := detectPfSense(conn, testTimeout)
	require.NoError(t, err)
	assert.True(t, detected, "should detect pfSense with only primary markers")
	require.NotNil(t, payload)
}

// TestDetectPfSense_NonPfSense verifies that a generic login page is not detected.
func TestDetectPfSense_NonPfSense(t *testing.T) {
	conn := mockConn(t, buildNonPfSensePage())
	defer conn.Close()

	payload, detected, err := detectPfSense(conn, testTimeout)
	require.NoError(t, err)
	assert.False(t, detected, "should not detect pfSense on generic login page")
	assert.Nil(t, payload)
}

// TestDetectPfSense_EmptyResponse verifies that an empty response returns an error (not a detection).
func TestDetectPfSense_EmptyResponse(t *testing.T) {
	conn := mockConn(t, buildEmptyResponse())
	defer conn.Close()

	_, detected, err := detectPfSense(conn, testTimeout)
	assert.Error(t, err, "empty response should produce an error")
	assert.False(t, detected)
}

// TestDetectPfSense_NonHTTPResponse verifies that non-HTTP data is not detected as pfSense.
func TestDetectPfSense_NonHTTPResponse(t *testing.T) {
	conn := mockConn(t, buildNonHTTPResponse())
	defer conn.Close()

	_, detected, err := detectPfSense(conn, testTimeout)
	// Non-HTTP (no \r\n\r\n) returns InvalidResponseError, not a false positive.
	assert.False(t, detected)
	_ = err // may or may not be an error; we only care it's not detected
}

// TestDetectPfSense_LighttpdServerHeader verifies version hinting for lighttpd.
func TestDetectPfSense_LighttpdServerHeader(t *testing.T) {
	conn := mockConn(t, buildPfSenseLoginPage("lighttpd/1.4.45", "", ""))
	defer conn.Close()

	payload, detected, err := detectPfSense(conn, testTimeout)
	require.NoError(t, err)
	assert.True(t, detected)
	require.NotNil(t, payload)
	assert.Equal(t, "lighttpd/1.4.45", payload.ServerInfo)
}

// TestDetectPfSense_NginxServerHeader verifies version hinting for nginx.
func TestDetectPfSense_NginxServerHeader(t *testing.T) {
	conn := mockConn(t, buildPfSenseLoginPage("nginx", "", ""))
	defer conn.Close()

	payload, detected, err := detectPfSense(conn, testTimeout)
	require.NoError(t, err)
	assert.True(t, detected)
	require.NotNil(t, payload)
	assert.Equal(t, "nginx", payload.ServerInfo)
}

// TestDetectPfSense_HostnameInTitle verifies hostname extraction from a custom title.
func TestDetectPfSense_HostnameInTitle(t *testing.T) {
	conn := mockConn(t, buildPfSenseLoginPage("", "fw01.example.com", ""))
	defer conn.Close()

	payload, detected, err := detectPfSense(conn, testTimeout)
	require.NoError(t, err)
	assert.True(t, detected)
	require.NotNil(t, payload)
	assert.Equal(t, "fw01.example.com", payload.Hostname)
}

// TestDetectPfSense_DefaultTitleNoHostname verifies no hostname is extracted from the default title.
func TestDetectPfSense_DefaultTitleNoHostname(t *testing.T) {
	conn := mockConn(t, buildPfSenseLoginPage("", "", ""))
	defer conn.Close()

	payload, detected, err := detectPfSense(conn, testTimeout)
	require.NoError(t, err)
	assert.True(t, detected)
	require.NotNil(t, payload)
	assert.Empty(t, payload.Hostname)
}

// --- CPE generation tests ---

func TestBuildPfSenseCPE(t *testing.T) {
	cpe := buildPfSenseCPE()
	assert.Equal(t, "cpe:2.3:a:netgate:pfsense:*:*:*:*:*:*:*:*", cpe)
}

// --- Version hint tests ---

func TestPfSenseVersionHint(t *testing.T) {
	tests := []struct {
		name       string
		serverInfo string
		wantPrefix string
	}{
		{"lighttpd_version", "lighttpd/1.4.45", "pre-2.3"},
		{"nginx_only", "nginx", "2.3+"},
		{"nginx_with_version", "nginx/1.21.6", "2.3+"},
		{"unknown_server", "Apache/2.4", ""},
		{"empty_server", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hint := pfSenseVersionHint(tt.serverInfo)
			if tt.wantPrefix == "" {
				assert.Empty(t, hint)
			} else {
				assert.Contains(t, hint, tt.wantPrefix)
			}
		})
	}
}

// --- extractServerInfo tests ---

func TestExtractServerInfo(t *testing.T) {
	tests := []struct {
		name     string
		headers  string
		expected string
	}{
		{
			name:     "lighttpd_header",
			headers:  "HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.45\r\nContent-Type: text/html",
			expected: "lighttpd/1.4.45",
		},
		{
			name:     "nginx_header",
			headers:  "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html",
			expected: "nginx",
		},
		{
			name:     "no_server_header",
			headers:  "HTTP/1.1 200 OK\r\nContent-Type: text/html",
			expected: "",
		},
		{
			name:     "case_insensitive_server",
			headers:  "HTTP/1.1 200 OK\r\nSERVER: lighttpd\r\n",
			expected: "lighttpd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractServerInfo(tt.headers)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// --- extractHostname tests ---

func TestExtractHostname(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "custom_hostname",
			body:     "<html><head><title>fw01.example.com - Login</title></head></html>",
			expected: "fw01.example.com",
		},
		{
			name:     "default_pfsense_title",
			body:     "<html><head><title>pfSense - Login</title></head></html>",
			expected: "",
		},
		{
			name:     "no_title_tag",
			body:     "<html><head></head><body></body></html>",
			expected: "",
		},
		{
			name:     "title_without_login_suffix",
			body:     "<html><head><title>Some Other Page</title></head></html>",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHostname(tt.body)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// --- Plugin interface tests ---

func TestPfSensePluginInterface(t *testing.T) {
	plugin := &PfSensePlugin{}

	assert.Equal(t, PFSENSE, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, 50, plugin.Priority())
	assert.True(t, plugin.PortPriority(80), "port 80 should be prioritized")
	assert.False(t, plugin.PortPriority(443), "port 443 should not be prioritized by TCP plugin")
	assert.False(t, plugin.PortPriority(8080))
}

func TestPfSenseTLSPluginInterface(t *testing.T) {
	plugin := &PfSenseTLSPlugin{}

	assert.Equal(t, PFSENSE_TLS, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, 50, plugin.Priority())
	assert.True(t, plugin.PortPriority(443), "port 443 should be prioritized")
	assert.False(t, plugin.PortPriority(80), "port 80 should not be prioritized by TLS plugin")
	assert.False(t, plugin.PortPriority(8443))
}

// --- Run() method tests ---

func TestPfSensePlugin_Run_Detected(t *testing.T) {
	plugin := &PfSensePlugin{}
	conn := mockConn(t, buildPfSenseLoginPage("nginx", "", ""))
	defer conn.Close()

	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.1:80"),
	}
	service, err := plugin.Run(conn, testTimeout, target)
	require.NoError(t, err)
	require.NotNil(t, service, "should return a service for detected pfSense")
	assert.Equal(t, "pfsense", service.Protocol)
}

func TestPfSensePlugin_Run_NotDetected(t *testing.T) {
	plugin := &PfSensePlugin{}
	conn := mockConn(t, buildNonPfSensePage())
	defer conn.Close()

	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.1:80"),
	}
	service, err := plugin.Run(conn, testTimeout, target)
	require.NoError(t, err)
	assert.Nil(t, service, "should return nil for non-pfSense page")
}

func TestPfSenseTLSPlugin_Run_Detected(t *testing.T) {
	plugin := &PfSenseTLSPlugin{}
	conn := mockConn(t, buildPfSenseLoginPage("nginx", "", ""))
	defer conn.Close()

	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.1:443"),
	}
	service, err := plugin.Run(conn, testTimeout, target)
	require.NoError(t, err)
	require.NotNil(t, service, "should return a service for detected pfSense over TLS")
	assert.Equal(t, "pfsense", service.Protocol)
}

func TestPfSenseTLSPlugin_Run_NotDetected(t *testing.T) {
	plugin := &PfSenseTLSPlugin{}
	conn := mockConn(t, buildNonPfSensePage())
	defer conn.Close()

	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.1:443"),
	}
	service, err := plugin.Run(conn, testTimeout, target)
	require.NoError(t, err)
	assert.Nil(t, service, "should return nil for non-pfSense page")
}

func TestPfSensePlugin_Run_EmptyResponse(t *testing.T) {
	plugin := &PfSensePlugin{}
	conn := mockConn(t, buildEmptyResponse())
	defer conn.Close()

	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.1:80"),
	}
	service, err := plugin.Run(conn, testTimeout, target)
	assert.Error(t, err, "empty response should produce an error")
	assert.Nil(t, service)
}

func TestPfSensePlugin_Run_VersionHint(t *testing.T) {
	plugin := &PfSensePlugin{}
	conn := mockConn(t, buildPfSenseLoginPage("lighttpd/1.4.45", "", ""))
	defer conn.Close()

	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.1:80"),
	}
	service, err := plugin.Run(conn, testTimeout, target)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.Contains(t, service.Version, "pre-2.3", "version should contain pre-2.3 for lighttpd")
}

// --- Additional detectPfSense branch tests ---

func TestDetectPfSense_SecondaryOnly(t *testing.T) {
	body := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
		`<html><body><span id="pfsense-logo-svg"><svg></svg></span></body></html>`
	conn := mockConn(t, []byte(body))
	defer conn.Close()

	payload, detected, err := detectPfSense(conn, testTimeout)
	require.NoError(t, err)
	assert.True(t, detected, "should detect pfSense with secondary marker only")
	require.NotNil(t, payload)
}

func TestDetectPfSense_RedirectResponse(t *testing.T) {
	resp := []byte("HTTP/1.1 302 Found\r\nLocation: /index.php\r\n\r\n")
	conn := mockConn(t, resp)
	defer conn.Close()

	_, detected, err := detectPfSense(conn, testTimeout)
	require.NoError(t, err)
	assert.False(t, detected, "302 redirect without pfSense markers should not detect")
}

func TestDetectPfSense_PartialPrimaryMarkers(t *testing.T) {
	body := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
		`<html><body><form><input name="usernamefld"/><input name="password"/></form></body></html>`
	conn := mockConn(t, []byte(body))
	defer conn.Close()

	_, detected, err := detectPfSense(conn, testTimeout)
	require.NoError(t, err)
	assert.False(t, detected, "should not detect with only one primary marker")
}

// --- Additional extractHostname branch test ---

func TestExtractHostname_MalformedTitleNoClose(t *testing.T) {
	body := "<html><head><title>fw01 - Login"
	got := extractHostname(body)
	assert.Equal(t, "", got, "malformed title without closing tag should return empty string")
}
