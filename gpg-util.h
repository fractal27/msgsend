#ifndef MSGSND_GPG_UTIL_H
#define MSGSND_GPG_UTIL_H

#include <stdio.h>
#include <gpgme.h>
#include <stdint.h>
#include <limits.h>

typedef struct {
       char *plaintext;               // decrypted message int signature_valid;           // 1 = valid, 0 = invalid, -1 = no signature
       int signature_valid;           // may be NULL
       char *signer_fingerprint;      // may be NULL
} decrypt_verify_result_t;

void
setup();

int
gpg_encrypt_and_sign(const char* plaintext, const char* key_id, 
              uint16_t n, const char* recipients[n],
              char** out_endbuf, size_t* out_sizendbuf);

decrypt_verify_result_t 
decrypt_and_verify_gpgme(const char *ciphertext);


char* 
userinput_identity_can_encrypt(void);

char* 
export_public_key(char* fpr);

bool 
is_key_usable(gpgme_key_t key);

void xdg_where_data(char xdg_home_data[PATH_MAX])
       __attribute((nonnull));
#endif // MSGSND_GPG_UTIL_H
