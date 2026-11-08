//go:build windows

package cli

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// FirewallConfig holds configuration for firewall rule setup
type FirewallConfig struct {
	Port     int
	Protocol string // "TCP" or "UDP" or "Both"
	RuleName string
}

// SetupFirewallException creates Windows Firewall exceptions for VX6 ports
func SetupFirewallException(port int, protocol string) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port number: %d", port)
	}

	if !isAdmin() {
		printFirewallManualSetupGuide(port)
		return fmt.Errorf("firewall rule setup requires administrator privileges; see instructions above or run with 'Run as administrator'")
	}

	ruleName := fmt.Sprintf("VX6 Peer Network - Port %d", port)

	// Create inbound rule
	if err := createFirewallRule(ruleName, port, "in", protocol); err != nil {
		return fmt.Errorf("failed to create inbound firewall rule: %w", err)
	}

	// Create outbound rule
	if err := createFirewallRule(ruleName, port, "out", protocol); err != nil {
		return fmt.Errorf("failed to create outbound firewall rule: %w", err)
	}

	return nil
}

// createFirewallRule adds a Windows Firewall rule using netsh
func createFirewallRule(ruleName string, port int, direction string, protocol string) error {
	// netsh advfirewall firewall add rule name="RuleName" dir=in/out action=allow protocol=tcp/udp localport=port

	protocols := []string{}
	if protocol == "TCP" || protocol == "Both" {
		protocols = append(protocols, "tcp")
	}
	if protocol == "UDP" || protocol == "Both" {
		protocols = append(protocols, "udp")
	}

	for _, proto := range protocols {
		args := []string{
			"advfirewall", "firewall", "add", "rule",
			fmt.Sprintf("name=%s (%s %s)", ruleName, proto, direction),
			fmt.Sprintf("dir=%s", direction),
			"action=allow",
			fmt.Sprintf("protocol=%s", proto),
			fmt.Sprintf("localport=%d", port),
			"enable=yes",
		}

		cmd := exec.Command("netsh", args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			// Rule might already exist, which is not an error
			outputStr := string(output)
			if !strings.Contains(outputStr, "already exists") && 
			   !strings.Contains(outputStr, "The object already exists") &&
			   !strings.Contains(outputStr, "error code 11001") {
				return fmt.Errorf("netsh error: %s", outputStr)
			}
		}
	}

	return nil
}

// isAdmin checks if the process has administrator privileges on Windows
// by attempting to run a netsh command that requires elevated privileges
func isAdmin() bool {
	// Try to run netsh add rule which requires admin privileges
	// We use a test rule name to avoid actually creating a rule if it fails
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name=VX6_ADMIN_TEST", "dir=in", "action=allow", "protocol=tcp",
		"localport=65535", "enable=no")
	output, err := cmd.CombinedOutput()
	if err == nil {
		// We were able to add a rule, so we're admin. Clean up the test rule.
		exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
			"name=VX6_ADMIN_TEST").Run()
		return true
	}
	
	// Check if the error is due to lack of admin privileges
	errStr := string(output)
	if strings.Contains(errStr, "access is denied") || 
	   strings.Contains(errStr, "Access Denied") ||
	   strings.Contains(errStr, "Access denied") {
		return false
	}
	
	// If it's the "already exists" error, that means we have admin privileges
	// but the rule already exists (which shouldn't happen with our test name)
	if strings.Contains(errStr, "already exists") || strings.Contains(errStr, "The object already exists") {
		return true
	}
	
	return false
}

// printFirewallManualSetupGuide prints instructions for manual firewall setup
func printFirewallManualSetupGuide(port int) {
	fmt.Println("\n--- Windows Firewall Setup Guide ---")
	fmt.Printf("Port %d needs firewall exceptions for VX6 to function correctly.\n\n", port)
	fmt.Println("Option 1: Run VX6 init again with Administrator privileges")
	fmt.Println("  - Right-click Command Prompt or PowerShell")
	fmt.Println("  - Select 'Run as administrator'")
	fmt.Printf("  - Run: vx6 init --name PREFIX --listen [::]: %d --setup-firewall\n\n", port)
	fmt.Println("Option 2: Manually add firewall rules using Windows Defender Firewall with Advanced Security")
	fmt.Println("  - Press Win+R, type 'wf.msc', press Enter")
	fmt.Println("  - Click 'Inbound Rules' → 'New Rule'")
	fmt.Printf("    - Rule Type: Port, Protocol: TCP/UDP, Specific local ports: %d\n", port)
	fmt.Println("    - Action: Allow, Apply to: All profiles")
	fmt.Printf("  - Repeat for Outbound Rules\n\n")
	fmt.Println("Option 3: Manually add firewall rules using netsh (in Administrator Command Prompt)")
	fmt.Printf("  netsh advfirewall firewall add rule name=\"VX6 Port %d (tcp in)\" dir=in action=allow protocol=tcp localport=%d enable=yes\n", port, port)
	fmt.Printf("  netsh advfirewall firewall add rule name=\"VX6 Port %d (tcp out)\" dir=out action=allow protocol=tcp localport=%d enable=yes\n", port, port)
	fmt.Printf("  netsh advfirewall firewall add rule name=\"VX6 Port %d (udp in)\" dir=in action=allow protocol=udp localport=%d enable=yes\n", port, port)
	fmt.Printf("  netsh advfirewall firewall add rule name=\"VX6 Port %d (udp out)\" dir=out action=allow protocol=udp localport=%d enable=yes\n", port, port)
	fmt.Println("-----------------------------------\n")
}

// ExtractPortFromAddress extracts port number from [addr]:port format
func ExtractPortFromAddress(addr string) (int, error) {
	// Handle IPv6 format like [::]:4242
	if strings.HasPrefix(addr, "[") {
		// Find the closing bracket
		closeBracketIdx := strings.Index(addr, "]")
		if closeBracketIdx == -1 {
			return 0, fmt.Errorf("invalid address format: %s", addr)
		}

		// Check if there's a port after the bracket
		if closeBracketIdx+1 < len(addr) && addr[closeBracketIdx+1] == ':' {
			portStr := addr[closeBracketIdx+2:]
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return 0, fmt.Errorf("invalid port in address %s: %w", addr, err)
			}
			return port, nil
		}
		return 0, fmt.Errorf("no port found in address: %s", addr)
	}

	// Handle regular IPv4 format with port
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("invalid address format: %s", addr)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("invalid port in address %s: %w", addr, err)
	}
	return port, nil
}

// RemoveFirewallException removes Windows Firewall exceptions for VX6 ports
func RemoveFirewallException(port int) error {
	if !isAdmin() {
		fmt.Println("Firewall rule removal requires administrator privileges.")
		return fmt.Errorf("please run with 'Run as administrator' to remove firewall rules")
	}

	ruleName := fmt.Sprintf("VX6 Peer Network - Port %d", port)

	// Remove for both TCP and UDP, inbound and outbound
	for _, proto := range []string{"tcp", "udp"} {
		for _, dir := range []string{"in", "out"} {
			args := []string{
				"advfirewall", "firewall", "delete", "rule",
				fmt.Sprintf("name=%s (%s %s)", ruleName, proto, dir),
			}

			cmd := exec.Command("netsh", args...)
			// Ignore errors if rule doesn't exist
			cmd.Run()
		}
	}

	return nil
}
