// version 1.0.1

package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	bip39 "github.com/cosmos/go-bip39"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)


// use BIP39 english wordlist
var Bip39WordList = bip39.WordList

// Network config
type Network struct {
	Name         string   `json:"name"`
	RpcURLs      []string `json:"rpc_urls"`
	ThresholdWei string   `json:"threshold_wei"`
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

	// Connect to all networks with multiple RPC endpoints
	networkConfigs := make(map[string]Network)
	thresholds := make(map[string]*big.Int)

	for _, network := range networks {
		if len(network.RpcURLs) == 0 {
			log.Printf("No RPC URLs for %s, skipping", network.Name)
			continue
		}
		networkConfigs[network.Name] = network
		threshold := new(big.Int)
		threshold.SetString(network.ThresholdWei, 10)
		thresholds[network.Name] = threshold
		fmt.Printf("Loaded %s with %d RPC endpoints\n", network.Name, len(network.RpcURLs))
		log.Printf("Loaded %s with %d RPC endpoints", network.Name, len(network.RpcURLs))
	}

	if len(networkConfigs) == 0 {
		log.Fatal("No networks available")
		return
	}

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
			for networkName, networkConfig := range networkConfigs {
				var balance *big.Int
				var successfulRPC string
				var lastErr error

				// Try each RPC endpoint until one succeeds
				for rpcIdx, rpcURL := range networkConfig.RpcURLs {
					client, err := ethclient.Dial(rpcURL)
					if err != nil {
						log.Printf("[%s] Failed to connect to RPC %d/%d: %v", networkName, rpcIdx+1, len(networkConfig.RpcURLs), err)
						lastErr = err
						continue
					}

					balance, err = client.BalanceAt(ctx, addr, nil)
					client.Close()

					if err != nil {
						log.Printf("[%s] Balance check failed on RPC %d/%d: %v", networkName, rpcIdx+1, len(networkConfig.RpcURLs), err)
						lastErr = err
						continue
					}

					// Success!
					successfulRPC = rpcURL
					break
				}

				// If all RPCs failed, show critical error
				if successfulRPC == "" {
					errMsg := fmt.Sprintf("[%s] CRITICAL: All %d RPC endpoints failed for %s. Last error: %v", networkName, len(networkConfig.RpcURLs), addr.Hex(), lastErr)
					fmt.Println("\n" + strings.Repeat("=", 70))
					fmt.Println("CRITICAL ERROR:")
					fmt.Println(errMsg)
					fmt.Println(strings.Repeat("=", 70))
					fmt.Println("\nPress Enter to continue...")
					log.Println(errMsg)
					fmt.Scanln()
					continue
				}

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


