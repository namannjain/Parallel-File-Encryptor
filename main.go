package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

func main() {
	inputDir := flag.String("in", "", "Input directory containing files to process")
	outputDir := flag.String("out", "", "Output directory for processed files")
	key := flag.String("key", "", "32-byte encryption/decryption key (64 hex characters)")
	mode := flag.String("mode", "encrypt", "Mode: 'encrypt' or 'decrypt'")
	flag.Parse()

	if *inputDir == "" || *outputDir == "" || *key == "" {
		fmt.Println("Usage: go run main.go -in [input_dir] -out [output_dir] -key [32_byte_key] -mode [encrypt|decrypt]")
		return
	}

	keyBytes, err := hex.DecodeString(*key)
	if err != nil || len(keyBytes) != 32 {
		fmt.Println("Invalid key. Must be 32 bytes (64 hex characters).")
		return
	}

	files, err := filepath.Glob(filepath.Join(*inputDir, "*"))
	if err != nil {
		fmt.Println("Error reading input directory:", err)
		return
	}

	numWorkers := runtime.NumCPU()
	jobs := make(chan string, len(files))
	results := make(chan error, len(files))

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg, keyBytes, *inputDir, *outputDir, *mode)
	}

	for _, file := range files {
		jobs <- file
	}
	close(jobs)

	wg.Wait()
	close(results)

	for err := range results {
		if err != nil {
			fmt.Println("Error:", err)
		}
	}

	fmt.Printf("%s complete!\n", *mode)
}

func worker(jobs <-chan string, results chan<- error, wg *sync.WaitGroup, key []byte, inputDir, outputDir, mode string) {
	defer wg.Done()
	for job := range jobs {
		var err error
		if mode == "encrypt" {
			err = encryptFile(job, key, inputDir, outputDir)
		} else if mode == "decrypt" {
			err = decryptFile(job, key, inputDir, outputDir)
		} else {
			err = fmt.Errorf("invalid mode: %s", mode)
		}
		results <- err
	}
}

func encryptFile(filename string, key []byte, inputDir, outputDir string) error {
	plaintext, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading file %s: %v", filename, err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating cipher for %s: %v", filename, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error creating GCM for %s: %v", filename, err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("error generating nonce for %s: %v", filename, err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	outputPath := filepath.Join(outputDir, filepath.Base(filename)+".enc")
	err = os.WriteFile(outputPath, ciphertext, 0644)
	if err != nil {
		return fmt.Errorf("error writing encrypted file %s: %v", outputPath, err)
	}

	fmt.Printf("Encrypted %s -> %s\n", filename, outputPath)
	return nil
}

func decryptFile(filename string, key []byte, inputDir, outputDir string) error {
	ciphertext, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading file %s: %v", filename, err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating cipher for %s: %v", filename, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error creating GCM for %s: %v", filename, err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return fmt.Errorf("ciphertext too short in file %s", filename)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("error decrypting file %s: %v", filename, err)
	}

	outputPath := filepath.Join(outputDir, strings.TrimSuffix(filepath.Base(filename), ".enc"))
	err = os.WriteFile(outputPath, plaintext, 0644)
	if err != nil {
		return fmt.Errorf("error writing decrypted file %s: %v", outputPath, err)
	}

	fmt.Printf("Decrypted %s -> %s\n", filename, outputPath)
	return nil
}
