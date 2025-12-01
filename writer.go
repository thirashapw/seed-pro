package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"time"
)

// Save funded wallets
func saveFunded(network string, index int, addr, priv, bal, mnemonic string, treasuryLog *os.File) {
	f, _ := os.OpenFile("funded.csv", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	defer f.Close()

	w := csv.NewWriter(f)
	_ = w.Write([]string{
		time.Now().Format(time.RFC3339),
		network,
		fmt.Sprintf("%d", index),
		addr,
		priv,
		bal,
		mnemonic,
	})
	w.Flush()

	log.Printf("FUNDED ACCOUNT SAVED: [%s] %s", network, addr)
	logToFile(treasuryLog, "FUNDED WALLET FOUND!")
	logToFile(treasuryLog, fmt.Sprintf("  Network: %s", network))
	logToFile(treasuryLog, fmt.Sprintf("  Mnemonic: %s", mnemonic))
	logToFile(treasuryLog, fmt.Sprintf("  Account Index: %d", index))
	logToFile(treasuryLog, fmt.Sprintf("  Address: %s", addr))
	logToFile(treasuryLog, fmt.Sprintf("  Private Key: %s", priv))
	logToFile(treasuryLog, fmt.Sprintf("  Balance: %s WEI", bal))
	logToFile(treasuryLog, "---")
}
