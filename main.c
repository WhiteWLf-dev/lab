/**
@mainpage

Utility for encrypting and decrypting files using the Triple DES (3DES) algorithm.
A user-provided password is converted into a key and initialization vector (IV) for 3DES.

@author Ushakov Aleksandr (anushakov@ispras.ru)
@date 10/20/2024
@version 1.0
*/


#include <openssl/evp.h>

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 1024*1024

/**
 * @brief Generates a key and initialization vector (IV) based on a password.
 * - The key is derived by applying a password-based key derivation function (PBKDF).
 * - A salt can be optionally provided, but in this implementation, it is not used (set to NULL).
 *
 * @param[in] password A string containing the password.
 * @param[out] key Buffer to store the generated key.
 * @param[out] iv Buffer to store the generated initialization vector (IV).
 * @return 1 on success, exits the program with an error message on failure.
 */
int generate_key_iv(const char *password, unsigned char *key, unsigned char *iv) {
  const EVP_CIPHER *cipher = EVP_des_ede3_cbc();
  const EVP_MD *dgst = EVP_sha256();
  if (!EVP_BytesToKey(cipher, dgst, NULL, (unsigned char *)password, strlen(password), 1, key, iv)) {
    fprintf(stderr, "Error occurred\n");
    exit(1);
  }
  return 1;
}

/**
 * @brief Encrypts the input file using the 3DES algorithm in CBC mode.
 *
 * @param[in] input_file Name of the input file to encrypt.
 * @param[in] output_file Name of the output file where the encrypted data will be written.
 * @param[in] password The password used to generate the key and IV.
 */
void encrypt_file(const char *input_file, const char *output_file, const char *password) {
  FILE *in = fopen(input_file, "rb");
  FILE *out = fopen(output_file, "wb");

  if (!in || !out) {
    fprintf(stderr, "Unable to open input or output file\n");
    exit(1);
  }

  unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

  // Generate key and IV from the password
  if (!generate_key_iv(password, key, iv)) {
    fprintf(stderr, "Error occurred\n");
    exit(1);
  }

  // Initialize encryption context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    fprintf(stderr, "Error occurred\n");
    exit(1);
  }

  if (1 != EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv)) {
    fprintf(stderr, "Error occurred\n");
    EVP_CIPHER_CTX_free(ctx);
    exit(1);
  }

  unsigned char inbuf[BUF_SIZE], outbuf[BUF_SIZE + EVP_CIPHER_block_size(EVP_des_ede3_cbc())];
  int num_bytes_read, out_len;

  // Encrypt file in blocks
  while ((num_bytes_read = fread(inbuf, 1, BUF_SIZE, in)) > 0) {
    if (1 != EVP_EncryptUpdate(ctx, outbuf, &out_len, inbuf, num_bytes_read)) {
      fprintf(stderr, "Error occurred\n");
      EVP_CIPHER_CTX_free(ctx);
      exit(1);
    }
    fwrite(outbuf, 1, out_len, out);
  }

  // Finalize encryption
  if (1 != EVP_EncryptFinal_ex(ctx, outbuf, &out_len)) {
    fprintf(stderr, "Error occurred\n");
    EVP_CIPHER_CTX_free(ctx);
    exit(1);
  }
  fwrite(outbuf, 1, out_len, out);

  EVP_CIPHER_CTX_free(ctx);
  fclose(in);
  fclose(out);
}

/**
 * @brief Decrypts the input file using the 3DES algorithm in CBC mode.
 *
 * @param[in] input_file Name of the input file to decrypt.
 * @param[in] output_file Name of the output file where the decrypted data will be written.
 * @param[in] password The password used to generate the key and IV.
 */
void decrypt_file(const char *input_file, const char *output_file, const char *password) {
  FILE *in = fopen(input_file, "rb");
  FILE *out = fopen(output_file, "wb");

  if (!in || !out) {
    fprintf(stderr, "Unable to open input or output file\n");
    exit(1);
  }

  unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

  // Generate key and IV from the password
  if (!generate_key_iv(password, key, iv)) {
    fprintf(stderr, "Error occurred\n");
    exit(1);
  }

  // Initialize decryption context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    fprintf(stderr, "Error occurred\n");
    exit(1);
  }

  if (1 != EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv)) {
    fprintf(stderr, "Error occurred\n");
    EVP_CIPHER_CTX_free(ctx);
    exit(1);
  }

  unsigned char inbuf[BUF_SIZE], outbuf[BUF_SIZE + EVP_CIPHER_block_size(EVP_des_ede3_cbc())];
  int num_bytes_read, out_len;

  // Decrypt file in blocks
  while ((num_bytes_read = fread(inbuf, 1, BUF_SIZE, in)) > 0) {
    if (1 != EVP_DecryptUpdate(ctx, outbuf, &out_len, inbuf, num_bytes_read)) {
      fprintf(stderr, "Error occurred\n");
      EVP_CIPHER_CTX_free(ctx);
      exit(1);
    }
    fwrite(outbuf, 1, out_len, out);
  }

  // Finalize decryption
  if (1 != EVP_DecryptFinal_ex(ctx, outbuf, &out_len)) {
    fprintf(stderr, "Error occurred\n");
    EVP_CIPHER_CTX_free(ctx);
    exit(1);
  }
  fwrite(outbuf, 1, out_len, out);

  EVP_CIPHER_CTX_free(ctx);
  fclose(in);
  fclose(out);
}

/**
 * @brief Prints the usage instructions for the program.
 *
 * @param[in] prog_name The name of the program invoked in the command line.
 */
void print_usage(const char *prog_name) {
  fprintf(stderr, "Usage: %s [-e|-d] -i input -o output -p password\n", prog_name);
  fprintf(stderr, "  -e : Encrypt the file\n");
  fprintf(stderr, "  -d : Decrypt the file\n");
  fprintf(stderr, "  -i : Input file\n");
  fprintf(stderr, "  -o : Output file\n");
  fprintf(stderr, "  -p : Password for encryption or decryption\n");
}

/**
 * @brief The main function of the program.
 *
 * Processes command-line arguments and runs either encryption or decryption.
 *
 * @param[in] argc The number of command-line arguments.
 * @param[in] argv Array of command-line arguments.
 * @return 0 on successful execution of the program.
 */
int main(int argc, char **argv) {
  int opt;
  int encrypt = -1;  // -1: not set, 0: decrypt, 1: encrypt
  char *input_file = NULL, *output_file = NULL, *password = NULL;

  // Process command-line arguments using getopt
  while ((opt = getopt(argc, argv, "edi:o:p:")) != -1) {
    switch (opt) {
    case 'e':
      encrypt = 1;
      break;
    case 'd':
      encrypt = 0;
      break;
    case 'i':
      input_file = optarg;
      break;
    case 'o':
      output_file = optarg;
      break;
    case 'p':
      password = optarg;
      break;
    default:
      print_usage(argv[0]);
      return 1;
    }
  }

  // Validate the input parameters
  if (encrypt == -1 || !input_file || !output_file || !password) {
    print_usage(argv[0]);
    return 1;
  }

  // Execute encryption or decryption
  if (encrypt == 1) {
    encrypt_file(input_file, output_file, password);
  } else {
    decrypt_file(input_file, output_file, password);
  }

  return 0;
}
