#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "api.h"

// Taille des buffers (définies dans api.h de PQClean)
uint8_t pk[CRYPTO_PUBLICKEYBYTES];     // Clé publique
uint8_t sk[CRYPTO_SECRETKEYBYTES];     // Clé privée
uint8_t sig[CRYPTO_BYTES];             // Signature
size_t siglen;
char message[64];                      // Message à signer (OTP basé sur timestamp)

int main() {
    // Étape 1 : Générer la paire de clés
    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "Erreur : échec de la génération des clés.\n");
        return 1;
    }

    // Étape 2 : Générer un message OTP basé sur l'horodatage
    time_t t = time(NULL);
    snprintf(message, sizeof(message), "OTP-%ld", t);
    printf("Message OTP à signer : %s\n", message);

    // Étape 3 : Signer le message
    if (crypto_sign_signature(sig, &siglen, (const uint8_t *)message, strlen(message), sk) != 0) {
        fprintf(stderr, "Erreur : échec de la signature.\n");
        return 1;
    }
    printf("Signature créée (%zu octets)\n", siglen);

    // Étape 4 : Vérifier la signature
    int verif = crypto_sign_verify(sig, siglen, (const uint8_t *)message, strlen(message), pk);
    if (verif == 0) {
        printf("✅ Signature valide. Authentification réussie.\n");
    } else {
        printf("❌ Signature invalide. Authentification échouée.\n");
    }

    return 0;
}
