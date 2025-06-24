#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "api.h"

#define ITERATIONS 100

uint8_t pk[CRYPTO_PUBLICKEYBYTES];
uint8_t sk[CRYPTO_SECRETKEYBYTES];
uint8_t sig[CRYPTO_BYTES];
size_t siglen;
char message[64];

long timediff(struct timeval start, struct timeval end) {
    return (end.tv_sec - start.tv_sec) * 1000000L + (end.tv_usec - start.tv_usec);
}

int main() {
    struct timeval t_start, t_end;
    long total_keygen_time = 0;
    long total_sign_time = 0;
    long total_verify_time = 0;

    printf("⏱  Benchmark sur %d itérations\n\n", ITERATIONS);

    for (int i = 0; i < ITERATIONS; i++) {
        // 1. Mesure du temps de génération des clés
        gettimeofday(&t_start, NULL);
        crypto_sign_keypair(pk, sk);
        gettimeofday(&t_end, NULL);
        total_keygen_time += timediff(t_start, t_end);

        // 2. Message OTP basé sur le timestamp
        time_t timestamp = time(NULL);
        snprintf(message, sizeof(message), "OTP-%ld", timestamp + i); // +i pour forcer la variation

        // 3. Signature
        gettimeofday(&t_start, NULL);
        crypto_sign_signature(sig, &siglen, (const uint8_t *)message, strlen(message), sk);
        gettimeofday(&t_end, NULL);
        total_sign_time += timediff(t_start, t_end);

        // 4. Vérification
        gettimeofday(&t_start, NULL);
        int verif = crypto_sign_verify(sig, siglen, (const uint8_t *)message, strlen(message), pk);
        gettimeofday(&t_end, NULL);
        total_verify_time += timediff(t_start, t_end);

        if (verif != 0) {
            fprintf(stderr, "❌ Erreur de vérification à l’itération %d\n", i);
            return 1;
        }
    }

    printf("✅ Toutes les vérifications ont réussi.\n\n");

    printf("🧪 Moyennes sur %d itérations :\n", ITERATIONS);
    printf("  🔑 Génération des clés   : %.2f ms\n", total_keygen_time / (ITERATIONS * 1000.0));
    printf("  ✍️  Signature d’OTP       : %.2f ms\n", total_sign_time / (ITERATIONS * 1000.0));
    printf("  ✅ Vérification signature : %.2f ms\n", total_verify_time / (ITERATIONS * 1000.0));

    return 0;
}
