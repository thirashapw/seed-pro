package main

import (
	"bufio"
	"os"
	"strings"
)

// Save a checked mnemonic to file
func saveCheckedMnemonic(filename, mnemonic string) {
	f, _ := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	defer f.Close()
	_, _ = f.WriteString(mnemonic + "\n")
}

// Load checked mnemonics from file
func loadCheckedMnemonics(filename string) map[string]bool {
	checked := make(map[string]bool)

	file, err := os.Open(filename)
	if err != nil {
		// File doesn't exist yet, return empty map
		return checked
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		mnemonic := strings.TrimSpace(scanner.Text())
		if mnemonic != "" {
			checked[mnemonic] = true
		}
	}

	return checked
}
