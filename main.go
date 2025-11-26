package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	bip39 "github.com/cosmos/go-bip39"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const accountCount = 4

// use BIP39 english wordlist
var Bip39WordList = bip39.WordList

// Network config
type Network struct {
	Name         string `json:"name"`
	RpcURL       string `json:"rpc_url"`
	ThresholdWei string `json:"threshold_wei"`
}

func main() {
	// logging
	_ = os.MkdirAll("logs", 0755)
	appLog, _ := os.OpenFile("logs/app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	validLog, _ := os.OpenFile("logs/valid.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	treasuryLog, _ := os.OpenFile("logs/treasury.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	log.SetOutput(appLog)

	// Load checked mnemonics
	checkedMnemonics := loadCheckedMnemonics("checked_seeds.txt")
	fmt.Printf("Loaded %d previously checked seeds\n", len(checkedMnemonics))
	log.Printf("Loaded %d previously checked seeds", len(checkedMnemonics))

	// Load networks from JSON
	networks, err := loadNetworks("networks.json")
	if err != nil {
		log.Fatalf("Failed to load networks: %v", err)
	}

	fmt.Printf("Loaded %d networks\n", len(networks))
	log.Printf("Loaded %d networks", len(networks))

	// Connect to all networks
	clients := make(map[string]*ethclient.Client)
	thresholds := make(map[string]*big.Int)

	for _, network := range networks {
		client, err := ethclient.Dial(network.RpcURL)
		if err != nil {
			log.Printf("Failed to connect to %s: %v", network.Name, err)
			fmt.Printf("Failed to connect to %s, skipping...\n", network.Name)
			continue
		}
		clients[network.Name] = client
		threshold := new(big.Int)
		threshold.SetString(network.ThresholdWei, 10)
		thresholds[network.Name] = threshold
		fmt.Printf("Connected to %s\n", network.Name)
		log.Printf("Connected to %s", network.Name)
	}

	if len(clients) == 0 {
		log.Fatal("No networks available")
		return
	}

	defer func() {
		for _, client := range clients {
			client.Close()
		}
	}()

	ctx := context.Background()

	// Infinite loop
	for {
		// Generate 12 random words
		words := random12Words()
		mnemonic := joinWords(words)

		fmt.Println("Generated words:")
		fmt.Println(mnemonic)
		log.Println("Generated:", mnemonic)

		// Validate mnemonic
		if !bip39.IsMnemonicValid(mnemonic) {
			fmt.Println("Not valid mnemonic. Skipping.")
			log.Println("Invalid. Skipping.")
			continue
		}

		// Check if already checked
		if checkedMnemonics[mnemonic] {
			fmt.Println("Already checked this mnemonic. Skipping.")
			log.Println("Already checked. Skipping.")
			continue
		}

		fmt.Println("Valid mnemonic found!")
		log.Println("Mnemonic VALID")
		logToFile(validLog, "VALID: "+mnemonic)

		// Mark as checked and save
		checkedMnemonics[mnemonic] = true
		saveCheckedMnemonic("checked_seeds.txt", mnemonic)

		seed := bip39.NewSeed(mnemonic, "")

		// MASTER KEY
		master, err := hdkeychain.NewMaster(seed, &chainParams)
		if err != nil {
			log.Printf("master key error: %v", err)
			continue
		}

		for i := 0; i < accountCount; i++ {
			priv, addr := deriveEthAccount(master, i)

			// Check balance on all networks
			for networkName, client := range clients {
				balance, _ := client.BalanceAt(ctx, addr, nil)
				fmt.Printf("[%s] Account %d: %s | Balance: %s\n", networkName, i, addr.Hex(), balance.String())

				// Log account info to valid.log
				logToFile(validLog, fmt.Sprintf("[%s] Account %d: %s | Balance: %s WEI", networkName, i, addr.Hex(), balance.String()))

				if balance.Cmp(thresholds[networkName]) >= 0 {
					saveFunded(
						networkName,
						i,
						addr.Hex(),
						fmt.Sprintf("0x%x", crypto.FromECDSA(priv)),
						balance.String(),
						mnemonic,
						treasuryLog,
					)
				}
			}
		}

		fmt.Println("Cycle complete. Starting new one...")
	}
}

// Dummy chain params (not used by Ethereum)
var chainParams = chaincfg.MainNetParams

// Generate 12 random words
func random12Words() []string {
	words := make([]string, 12)
	for i := 0; i < 12; i++ {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(Bip39WordList))))
		words[i] = Bip39WordList[idx.Int64()]
	}
	return words
}

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

// Derive m/44'/60'/0'/0/index using btcsuite hdkeychain
func deriveEthAccount(master *hdkeychain.ExtendedKey, index int) (*ecdsa.PrivateKey, common.Address) {

	// m/44'
	purpose, err := master.Derive(harden(44))
	if err != nil {
		log.Fatalf("purpose err: %v", err)
	}

	// m/44'/60'
	coinType, err := purpose.Derive(harden(60))
	if err != nil {
		log.Fatalf("coinType err: %v", err)
	}

	// m/44'/60'/0'
	account, err := coinType.Derive(harden(0))
	if err != nil {
		log.Fatalf("account err: %v", err)
	}

	// m/44'/60'/0'/0
	change, err := account.Derive(0)
	if err != nil {
		log.Fatalf("change err: %v", err)
	}

	// m/44'/60'/0'/0/index
	child, err := change.Derive(uint32(index))
	if err != nil {
		log.Fatalf("index err: %v", err)
	}

	// get private key
	key, err := child.ECPrivKey()
	if err != nil {
		log.Fatalf("ECPrivKey err: %v", err)
	}

	// convert to go-ethereum ECDSA
	priv := key.ToECDSA()
	addr := crypto.PubkeyToAddress(priv.PublicKey)

	return priv, addr
}

func harden(i uint32) uint32 {
	return i + hdkeychain.HardenedKeyStart
}

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

// Helper to log to specific file
func logToFile(file *os.File, message string) {
	timestamp := time.Now().Format(time.RFC3339)
	_, _ = file.WriteString(fmt.Sprintf("%s | %s\n", timestamp, message))
}

// Load networks from JSON file
func loadNetworks(filename string) ([]Network, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var networks []Network
	err = json.Unmarshal(data, &networks)
	if err != nil {
		return nil, err
	}

	return networks, nil
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

// Save a checked mnemonic to file
func saveCheckedMnemonic(filename, mnemonic string) {
	f, _ := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	defer f.Close()
	_, _ = f.WriteString(mnemonic + "\n")
}
