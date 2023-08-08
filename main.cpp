#include <openssl/aes.h>
#include <iostream>
#include <string>
#include <cstring>

using namespace std;

int main() {
    string message = "Este es un mensaje secreto";
    unsigned char key[AES_BLOCK_SIZE] = "01234567890123456789012345678901";
    unsigned char iv[AES_BLOCK_SIZE] = "0123456789012345";

    // Encriptación
    AES_KEY aesKey;
    AES_set_encrypt_key(key, 256, &aesKey);
    unsigned char encryptedMessage[message.size() + AES_BLOCK_SIZE];
    memset(encryptedMessage, 0, sizeof(encryptedMessage));
    AES_cbc_encrypt((const unsigned char*) message.c_str(), encryptedMessage, message.size(), &aesKey, iv, AES_ENCRYPT);

    // Desencriptación
    AES_set_decrypt_key(key, 256, &aesKey);
    unsigned char decryptedMessage[message.size() + AES_BLOCK_SIZE];
    memset(decryptedMessage, 0, sizeof(decryptedMessage));
    AES_cbc_encrypt(encryptedMessage, decryptedMessage, message.size(), &aesKey, iv, AES_DECRYPT);

    // Mostrar resultados
    cout << "Mensaje original: " << message << endl;
    cout << "Mensaje encriptado: " << encryptedMessage << endl;
    cout << "Mensaje desencriptado: " << decryptedMessage << endl;

    return 0;
}
