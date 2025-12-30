// Package main demonstrates the comprehensive usage of the SD-JWT library.
// This CLI tool allows you to run individual demos or all demos at once.
//
// Usage:
//
//	go run ./examples              # Show demo menu
//	go run ./examples list         # List all available demos
//	go run ./examples all          # Run all demos
//	go run ./examples <demo>       # Run a specific demo (e.g., basic, nested, vc)
//
// Available demos:
//   - basic: Basic SD-JWT flow (issue, present, verify)
//   - nested: Nested claims with selective disclosure
//   - arrays: Array element selective disclosure
//   - serialization: Serialization formats (compact, flatten JSON, general JSON)
//   - vc: SD-JWT VC (Verifiable Credentials)
//   - status: Status list for credential revocation
//   - metadata: VCT metadata structures
//   - signer: Custom signer interface (HSM/KMS integration)
//   - eaa: ETSI TS 119 472-1 EAA (Electronic Attestation)
package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/georgepadayatti/sdjwt/signer"
)

// Demo represents a runnable demo
type Demo struct {
	Name        string
	Description string
	Run         func(issuerSigner signer.Signer, holderSigner signer.Signer, holderPubJWK []byte)
}

// demos is the list of available demos
var demos = []Demo{
	{
		Name:        "basic",
		Description: "Basic SD-JWT flow (issue, present, verify)",
		Run: func(issuerSigner, holderSigner signer.Signer, holderPubJWK []byte) {
			demoBasicSDJWT(issuerSigner, holderSigner, holderPubJWK)
		},
	},
	{
		Name:        "nested",
		Description: "Nested claims with selective disclosure",
		Run: func(issuerSigner, holderSigner signer.Signer, holderPubJWK []byte) {
			demoNestedClaims(issuerSigner, holderSigner, holderPubJWK)
		},
	},
	{
		Name:        "arrays",
		Description: "Array element selective disclosure",
		Run: func(issuerSigner, holderSigner signer.Signer, holderPubJWK []byte) {
			demoArrayElements(issuerSigner)
		},
	},
	{
		Name:        "serialization",
		Description: "Serialization formats (compact, flatten JSON, general JSON)",
		Run: func(issuerSigner, holderSigner signer.Signer, holderPubJWK []byte) {
			demoJSONSerialization(issuerSigner)
		},
	},
	{
		Name:        "vc",
		Description: "SD-JWT VC (Verifiable Credentials) - draft-13",
		Run: func(issuerSigner, holderSigner signer.Signer, holderPubJWK []byte) {
			demoSDJWTVC(issuerSigner, holderSigner, holderPubJWK)
		},
	},
	{
		Name:        "status",
		Description: "Status list for credential revocation",
		Run: func(issuerSigner, holderSigner signer.Signer, holderPubJWK []byte) {
			demoStatusList(issuerSigner)
		},
	},
	{
		Name:        "metadata",
		Description: "VCT metadata structures",
		Run: func(issuerSigner, holderSigner signer.Signer, holderPubJWK []byte) {
			demoVCTMetadata()
		},
	},
	{
		Name:        "signer",
		Description: "Custom signer interface (HSM/KMS integration)",
		Run: func(issuerSigner, holderSigner signer.Signer, holderPubJWK []byte) {
			demoCustomSigner(issuerSigner, holderSigner, holderPubJWK)
		},
	},
	{
		Name:        "eaa",
		Description: "ETSI TS 119 472-1 EAA (Electronic Attestation)",
		Run: func(issuerSigner, holderSigner signer.Signer, holderPubJWK []byte) {
			demoETSIEAA(issuerSigner, holderSigner, holderPubJWK)
		},
	},
}

func main() {
	// Parse command-line arguments
	args := os.Args[1:]

	if len(args) == 0 {
		// No arguments - show interactive menu
		showInteractiveMenu()
		return
	}

	command := strings.ToLower(args[0])

	switch command {
	case "list", "-l", "--list":
		listDemos()
	case "all", "-a", "--all":
		runAllDemos()
	case "help", "-h", "--help":
		showHelp()
	default:
		// Try to run specific demo
		runDemo(command)
	}
}

func showHeader() {
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║           SD-JWT Go Library - Comprehensive Demo                 ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

func showHelp() {
	fmt.Println("SD-JWT Go Library - Demo CLI")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  go run ./examples              Show interactive demo menu")
	fmt.Println("  go run ./examples list         List all available demos")
	fmt.Println("  go run ./examples all          Run all demos")
	fmt.Println("  go run ./examples <demo>       Run a specific demo")
	fmt.Println("  go run ./examples help         Show this help message")
	fmt.Println()
	fmt.Println("Available demos:")
	for _, demo := range demos {
		fmt.Printf("  %-15s %s\n", demo.Name, demo.Description)
	}
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  go run ./examples basic        Run basic SD-JWT demo")
	fmt.Println("  go run ./examples vc           Run SD-JWT VC demo")
	fmt.Println("  go run ./examples eaa          Run ETSI EAA demo")
}

func listDemos() {
	fmt.Println("Available Demos:")
	fmt.Println()
	for i, demo := range demos {
		fmt.Printf("  %d. %-15s %s\n", i+1, demo.Name, demo.Description)
	}
	fmt.Println()
	fmt.Println("Run with: go run ./examples <demo-name>")
	fmt.Println("Run all:  go run ./examples all")
}

func showInteractiveMenu() {
	showHeader()
	fmt.Println("Select a demo to run:")
	fmt.Println()
	for i, demo := range demos {
		fmt.Printf("  [%d] %-15s %s\n", i+1, demo.Name, demo.Description)
	}
	fmt.Println()
	fmt.Printf("  [%d] %-15s %s\n", len(demos)+1, "all", "Run all demos")
	fmt.Printf("  [%d] %-15s %s\n", 0, "exit", "Exit")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter your choice (number or name): ")
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input:", err)
		return
	}

	input = strings.TrimSpace(strings.ToLower(input))

	// Check if it's a number
	if num, err := strconv.Atoi(input); err == nil {
		if num == 0 {
			fmt.Println("Goodbye!")
			return
		}
		if num == len(demos)+1 {
			runAllDemos()
			return
		}
		if num >= 1 && num <= len(demos) {
			runDemoByIndex(num - 1)
			return
		}
		fmt.Printf("Invalid choice: %d. Please enter a number between 0 and %d.\n", num, len(demos)+1)
		return
	}

	// Check if it's "all" or "exit"
	if input == "all" {
		runAllDemos()
		return
	}
	if input == "exit" || input == "quit" || input == "q" {
		fmt.Println("Goodbye!")
		return
	}

	// Try to match by name
	runDemo(input)
}

func runDemo(name string) {
	for i, demo := range demos {
		if strings.EqualFold(demo.Name, name) {
			runDemoByIndex(i)
			return
		}
	}

	// Try partial match
	for i, demo := range demos {
		if strings.Contains(strings.ToLower(demo.Name), strings.ToLower(name)) ||
			strings.Contains(strings.ToLower(demo.Description), strings.ToLower(name)) {
			fmt.Printf("Running demo matching '%s': %s\n\n", name, demo.Name)
			runDemoByIndex(i)
			return
		}
	}

	fmt.Printf("Unknown demo: %s\n\n", name)
	fmt.Println("Available demos:")
	for _, demo := range demos {
		fmt.Printf("  %-15s %s\n", demo.Name, demo.Description)
	}
	os.Exit(1)
}

func runDemoByIndex(index int) {
	if index < 0 || index >= len(demos) {
		fmt.Println("Invalid demo index")
		return
	}

	demo := demos[index]
	showHeader()

	// Generate signers
	issuerSigner, holderSigner, holderPubJWK := generateSigners()

	fmt.Printf("Running: %s - %s\n", demo.Name, demo.Description)
	fmt.Println()

	demo.Run(issuerSigner, holderSigner, holderPubJWK)

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                       Demo Completed!                            ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
}

func runAllDemos() {
	showHeader()

	// Generate signers once for all demos
	issuerSigner, holderSigner, holderPubJWK := generateSigners()

	for _, demo := range demos {
		demo.Run(issuerSigner, holderSigner, holderPubJWK)
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    All Demos Completed!                          ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
}

func generateSigners() (signer.Signer, signer.Signer, []byte) {
	issuerSigner, err := signer.NewDefaultSigner()
	if err != nil {
		fmt.Printf("failed to create issuer signer: %v\n", err)
		os.Exit(1)
	}
	holderSigner, err := signer.NewDefaultSigner()
	if err != nil {
		fmt.Printf("failed to create holder signer: %v\n", err)
		os.Exit(1)
	}
	holderPubJWK := publicKeyToJWK(holderSigner.PublicKey())
	if holderPubJWK == nil {
		fmt.Println("failed to convert holder public key to JWK")
		os.Exit(1)
	}
	return issuerSigner, holderSigner, holderPubJWK
}
