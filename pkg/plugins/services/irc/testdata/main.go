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

// Mock IRC server for plugin integration testing.
//
// Configuration via environment variables:
//
//	IRC_PORT         - listening port (default: 6667)
//	IRC_SERVER_NAME  - server hostname (default: irc.mock.local)
//	IRC_NETWORK_NAME - IRC network name (default: MockNet)
//	IRC_DAEMON       - server daemon/version string (default: MockIRCd-1.0.0)
//	IRC_USER_COUNT   - reported user count (default: 10)
//	IRC_CHANNEL_COUNT - reported channel count (default: 5)
//
// Usage:
//
//	docker build -t irc-test .
//	docker run -d --name irc-test -p 6667:6667/tcp irc-test
//	nerva -t 127.0.0.1:6667 --verbose
//	docker stop irc-test && docker rm irc-test
package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return fallback
}

type config struct {
	serverName   string
	networkName  string
	daemon       string
	userCount    int
	channelCount int
}

func loadConfig() config {
	return config{
		serverName:   getEnv("IRC_SERVER_NAME", "irc.mock.local"),
		networkName:  getEnv("IRC_NETWORK_NAME", "MockNet"),
		daemon:       getEnv("IRC_DAEMON", "MockIRCd-1.0.0"),
		userCount:    getEnvInt("IRC_USER_COUNT", 10),
		channelCount: getEnvInt("IRC_CHANNEL_COUNT", 5),
	}
}

// sendLine writes a formatted IRC message to the connection.
func sendLine(conn net.Conn, format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(line, "\r\n") {
		line += "\r\n"
	}
	_, _ = conn.Write([]byte(line))
}

// handleConnection handles a single IRC client connection.
func handleConnection(conn net.Conn, cfg config) {
	defer conn.Close()

	nick := "unknown"
	scanner := bufio.NewScanner(conn)

	// Read NICK and USER commands from client
	for scanner.Scan() {
		line := scanner.Text()
		upper := strings.ToUpper(strings.TrimSpace(line))

		if strings.HasPrefix(upper, "NICK ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				nick = parts[1]
			}
		} else if strings.HasPrefix(upper, "USER ") {
			// We have both NICK and USER; send welcome burst
			break
		}
	}

	// RPL_WELCOME (001)
	sendLine(conn, ":%s 001 %s :Welcome to the %s Internet Relay Chat Network %s",
		cfg.serverName, nick, cfg.networkName, nick)

	// RPL_YOURHOST (002)
	sendLine(conn, ":%s 002 %s :Your host is %s, running version %s",
		cfg.serverName, nick, cfg.serverName, cfg.daemon)

	// RPL_CREATED (003)
	sendLine(conn, ":%s 003 %s :This server was created 2024-01-01",
		cfg.serverName, nick)

	// RPL_MYINFO (004) - split daemon into software and version
	userModes := "aioqrs"
	channelModes := "beIklmnoOpqrstv"
	sendLine(conn, ":%s 004 %s %s %s %s %s",
		cfg.serverName, nick, cfg.serverName, cfg.daemon, userModes, channelModes)

	// RPL_ISUPPORT (005)
	sendLine(conn, ":%s 005 %s CHANTYPES=# NETWORK=%s PREFIX=(ov)@+ :are supported by this server",
		cfg.serverName, nick, cfg.networkName)

	// RPL_LUSERCLIENT (251)
	sendLine(conn, ":%s 251 %s :There are %d users and 0 services on 1 servers",
		cfg.serverName, nick, cfg.userCount)

	// RPL_LUSERCHANNELS (254)
	sendLine(conn, ":%s 254 %s %d :channels formed",
		cfg.serverName, nick, cfg.channelCount)

	// MOTD end
	sendLine(conn, ":%s 376 %s :End of /MOTD command",
		cfg.serverName, nick)

	// Wait for QUIT or connection close
	for scanner.Scan() {
		line := scanner.Text()
		upper := strings.ToUpper(strings.TrimSpace(line))
		if strings.HasPrefix(upper, "QUIT") {
			sendLine(conn, "ERROR :Closing Link: %s (Quit)", nick)
			return
		}
	}
}

func main() {
	port := getEnv("IRC_PORT", "6667")
	cfg := loadConfig()

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Failed to listen on :%s: %v", port, err)
	}
	defer ln.Close()

	log.Printf("Mock IRC server listening on :%s (network=%s, daemon=%s)",
		port, cfg.networkName, cfg.daemon)

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Println("Shutting down mock IRC server")
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Check if we're shutting down
			select {
			case <-quit:
				return
			default:
				// Log non-shutdown errors but keep running
				log.Printf("Accept error: %v", err)
				continue
			}
		}
		go handleConnection(conn, cfg)
	}
}
