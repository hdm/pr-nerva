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

/*
pfSense Web Interface Fingerprinting

This plugin implements pfSense firewall detection via HTTP/HTTPS login page analysis.
pfSense exposes a distinctive login page at / with unique HTML markers that are
not present in other web applications.

Detection Strategy:
  PHASE 1 - DETECTION (determines if the service is pfSense):
    - Send HTTP GET / request to root endpoint
    - Parse HTML response for pfSense-specific markers:
      PRIMARY:   name="usernamefld" AND name="passwordfld" (form fields unique to pfSense)
      SECONDARY: id="pfsense-logo-svg" (inline SVG logo)
      TERTIARY:  class="loginCont" (CSS login container class)
    - Must match PRIMARY or SECONDARY to confirm detection

  PHASE 2 - ENRICHMENT (best-effort version hinting):
    - Extract Server header from HTTP response
    - "lighttpd" in Server header → version hint "pre-2.3"
    - "nginx" in Server header → version hint "2.3+"
    - Exact version not available on login page; CPE version uses "*"

pfSense Login Page Markers:
  - name="usernamefld": username field in login form (unique to pfSense)
  - name="passwordfld": password field in login form (unique to pfSense)
  - id="pfsense-logo-svg": inline SVG element containing the pfSense logo
  - class="loginCont": CSS class for login container div

Server Header Version Mapping:
  - lighttpd → pfSense pre-2.3 (older versions used lighttpd)
  - nginx    → pfSense 2.3+ (newer versions switched to nginx)

CPE: cpe:2.3:a:netgate:pfsense:*:*:*:*:*:*:*:*
*/

package pfsense

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	PFSENSE    = "pfsense"
	PFSENSE_TLS = "pfsenseTLS"

	DefaultPfSensePort    = 80
	DefaultPfSenseTLSPort = 443
)

type PfSensePlugin struct{}
type PfSenseTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&PfSensePlugin{})
	plugins.RegisterPlugin(&PfSenseTLSPlugin{})
}

// buildPfSenseCPE constructs a CPE string for pfSense.
// Version is always "*" because the login page does not expose the version.
func buildPfSenseCPE() string {
	return "cpe:2.3:a:netgate:pfsense:*:*:*:*:*:*:*:*"
}

// extractServerInfo extracts the Server header value from a raw HTTP response.
// Returns the trimmed Server header value, or empty string if not present.
func extractServerInfo(response string) string {
	for _, line := range strings.Split(response, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			return strings.TrimSpace(line[len("server:"):])
		}
	}
	return ""
}

// extractHostname extracts the hostname from an HTML <title> tag.
// pfSense titles follow the pattern "[hostname] - Login" or "pfSense - Login".
// Returns empty string if no hostname prefix is found.
func extractHostname(body string) string {
	titleStart := strings.Index(strings.ToLower(body), "<title>")
	if titleStart == -1 {
		return ""
	}
	titleEnd := strings.Index(strings.ToLower(body[titleStart:]), "</title>")
	if titleEnd == -1 {
		return ""
	}
	title := body[titleStart+len("<title>") : titleStart+titleEnd]
	title = strings.TrimSpace(title)

	// Pattern: "[hostname] - Login"
	// If title is exactly "pfSense - Login" there is no custom hostname prefix
	const loginSuffix = " - Login"
	if !strings.HasSuffix(title, loginSuffix) {
		return ""
	}
	prefix := strings.TrimSuffix(title, loginSuffix)
	if strings.EqualFold(prefix, "pfSense") {
		return ""
	}
	return prefix
}

// detectPfSense performs HTTP detection of the pfSense web interface.
// Returns detected ServicePfSense payload and bool, or nil/false for non-matches.
func detectPfSense(conn net.Conn, timeout time.Duration) (*plugins.ServicePfSense, bool, error) {
	httpRequest := "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

	response, err := utils.SendRecv(conn, []byte(httpRequest), timeout)
	if err != nil {
		return nil, false, err
	}
	if len(response) == 0 {
		return nil, false, &utils.InvalidResponseError{Service: PFSENSE}
	}

	responseStr := string(response)

	// Extract body after header separator
	bodyStart := strings.Index(responseStr, "\r\n\r\n")
	if bodyStart == -1 {
		return nil, false, &utils.InvalidResponseError{Service: PFSENSE}
	}
	body := responseStr[bodyStart+4:]

	// PRIMARY detection: both username and password field names must be present
	primaryMatch := strings.Contains(body, `name="usernamefld"`) &&
		strings.Contains(body, `name="passwordfld"`)

	// SECONDARY detection: pfSense SVG logo element
	secondaryMatch := strings.Contains(body, `id="pfsense-logo-svg"`)

	if !primaryMatch && !secondaryMatch {
		return nil, false, nil
	}

	// Extract Server header for version hinting
	serverInfo := extractServerInfo(responseStr[:bodyStart])

	// Extract hostname from title
	hostname := extractHostname(body)

	payload := &plugins.ServicePfSense{
		CPEs:       []string{buildPfSenseCPE()},
		ServerInfo: serverInfo,
		Hostname:   hostname,
	}

	return payload, true, nil
}

func (p *PfSensePlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	payload, detected, err := detectPfSense(conn, timeout)
	if err != nil {
		return nil, err
	}
	if !detected {
		return nil, nil
	}

	// Determine version hint from server header
	version := pfSenseVersionHint(payload.ServerInfo)

	return plugins.CreateServiceFrom(target, *payload, false, version, plugins.TCP), nil
}

func (p *PfSensePlugin) PortPriority(port uint16) bool {
	return port == DefaultPfSensePort
}

func (p *PfSensePlugin) Name() string {
	return PFSENSE
}

func (p *PfSensePlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *PfSensePlugin) Priority() int {
	return 50
}

func (p *PfSenseTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	payload, detected, err := detectPfSense(conn, timeout)
	if err != nil {
		return nil, err
	}
	if !detected {
		return nil, nil
	}

	version := pfSenseVersionHint(payload.ServerInfo)

	return plugins.CreateServiceFrom(target, *payload, true, version, plugins.TCPTLS), nil
}

func (p *PfSenseTLSPlugin) PortPriority(port uint16) bool {
	return port == DefaultPfSenseTLSPort
}

func (p *PfSenseTLSPlugin) Name() string {
	return PFSENSE_TLS
}

func (p *PfSenseTLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *PfSenseTLSPlugin) Priority() int {
	return 50
}

// pfSenseVersionHint returns a version hint string based on the Server header.
// Returns empty string if no useful hint can be derived.
func pfSenseVersionHint(serverInfo string) string {
	lower := strings.ToLower(serverInfo)
	if strings.Contains(lower, "lighttpd") {
		return fmt.Sprintf("pre-2.3 (%s)", serverInfo)
	}
	if strings.Contains(lower, "nginx") {
		return fmt.Sprintf("2.3+ (%s)", serverInfo)
	}
	return ""
}
