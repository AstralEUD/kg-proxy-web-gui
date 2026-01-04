package system

import (
	"fmt"
	"os/exec"
	"runtime"
)

type CommandExecutor interface {
	Execute(command string, args ...string) (string, error)
	GetOS() string
}

type RealExecutor struct{}

func (e *RealExecutor) Execute(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (e *RealExecutor) GetOS() string {
	return runtime.GOOS
}

type MockExecutor struct{}

func (e *MockExecutor) Execute(command string, args ...string) (string, error) {
	// Simulate success for common commands
	fmt.Printf("[MockExecutor] Executing: %s %v\n", command, args)
	
	if command == "wg" && len(args) > 0 && args[0] == "genkey" {
		return "MB9k...MockPrivateKey...", nil
	}
	if command == "wg" && len(args) > 0 && args[0] == "pubkey" {
		return "PB9k...MockPublicKey...", nil
	}
	
	return "Mock Success", nil
}

func (e *MockExecutor) GetOS() string {
	return "mock-" + runtime.GOOS
}

func NewExecutor() CommandExecutor {
	if runtime.GOOS == "windows" {
		return &MockExecutor{}
	}
	return &RealExecutor{}
}
