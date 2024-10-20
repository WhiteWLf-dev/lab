# 3DES File Encryption/Decryption Utility

This command-line utility allows you to encrypt and decrypt files using the Triple DES (3DES) algorithm in CBC mode. The cryptographic key and initialization vector (IV) are derived from a user-provided password using OpenSSL's key derivation functions.

## Features

- **Encryption**: Encrypt files using the 3DES (Triple DES) algorithm in CBC mode.
- **Decryption**: Decrypt previously encrypted files.
- **Password-Based Key Derivation**: The key and IV are derived securely from the user’s password using SHA-256.

## Prerequisites

- OpenSSL development libraries (`libssl-dev`)
- CMake
- A C compiler (e.g., `gcc`)

Make sure OpenSSL is installed on your system. If not, you can install it using a package manager. For example:

### On Ubuntu/Debian:
```bash
sudo apt-get install gcc libssl-dev cmake
```
### On Fedora:
```bash
sudo dnf install gcc openssl-devel cmake
```
### On macOS (with Homebrew):
```bash
brew install gcc openssl cmake
```

## Building the Utility

To compile the program, follow these steps:

1. Clone the Repository (if applicable):

   ```bash
   git clone https://git.miem.hse.ru/anushakov/lab2.git
   cd lab2
   ```

2. Run CMake: this command generates the necessary build files based on the CMakeLists.txt configuration:

   ```bash
   cmake -S . -B build
   ```

3. Build program:

   ```bash
   cd build
   make
   ```
## Usage
The utility takes several command-line arguments to specify whether you want to encrypt or decrypt a file, along with input, output, and password parameters.

```bash
./des [-e|-d] -i input -o output -p password
```

Options:

- -e : Encrypt the input file
- -d : Decrypt the input file
- -i : Path to the input file
- -o : Path to the output file
- -p : Password to use for encryption or decryption

## Example Usage
### Encrypt a File
To encrypt a file named plaintext.txt and output it as encrypted.dat:

```bash
./des -e -i plaintext.txt -o encrypted.dat -p your_password
```

### Decrypt a File
To decrypt the encrypted.dat file back to decrypted.txt:

```bash
./des -d -i encrypted.dat -o decrypted.txt -p your_password
```

## Contributing
Contributions are welcome! Please feel free to submit issues and pull requests.

## Licensing and distribution

Utility is distributed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Acknowledgements
This utility uses the OpenSSL library for cryptographic operations.
