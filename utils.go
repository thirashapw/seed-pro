package main

import (
	"fmt"
	"os"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

func joinWords(words []string) string {
	out := ""
	for i, w := range words {
		if i > 0 {
			out += " "
		}
		out += w
	}
	return out
}

func harden(i uint32) uint32 {
	return i + hdkeychain.HardenedKeyStart
}

// Helper to log to specific file
func logToFile(file *os.File, message string) {
	timestamp := time.Now().Format(time.RFC3339)
	_, _ = file.WriteString(fmt.Sprintf("%s | %s\n", timestamp, message))
}
