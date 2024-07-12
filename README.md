## Overview
A command-line application written in Go that allows for encrypting and decrypting data using AES.
It provides a simple and straightforward way to protect sensitive data and ensure that it can only be accessed by authorized users.

## Features
1. It uses command-line flags to get the input directory, output directory, encryption key and mode (to encrypt or decrypt)
2. It creates a worker pool with as many workers as there are CPU cores
3. Each worker reads file from the input directory, encrypts them using AES or decrypts them and writes the encrypted/decrypted file to output folder.
4. Done in parallel with each worker pool processing files concurrently.

## Getting Started
1. For encryption

  go run main.go -in [input_directory] -out [output_directory] -key [32_byte_key] -mode encrypt

2. For decryption

  go run main.go -in [encrypted_directory] -out [decrypted_directory] -key [32_byte_key] -mode decrypt

Replace [input_directory], [output_directory], [encrypted_directory], [decrypted_directory], and [32_byte_key] with appropriate values.

3. For generating a unique 32 byte key, use the command

  openssl rand -hex 32
  
