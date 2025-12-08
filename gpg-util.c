#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <stdbool.h>
#include <gpgme.h>
#include <stdint.h>
#include "gpg-util.h"

#ifndef GPG_USING_ARMOR
#define GPG_USING_ARMOR       1 // set to 1 for true
#endif // GPG_USING_ARMOR

#define return_if_err(err,return_val)                      \
       do  {                                               \
              if (err)                                     \
              {                                            \
                     fprintf(stderr, "%s:%d: %s: %s\n",    \
                                   __FILE__, __LINE__,     \
                                   gpgme_strsource(err),   \
                                   gpgme_strerror(err));   \
                     return return_val;                    \
              }                                            \
       } while (0)


// Global variables
char gpg_pubkey_where[PATH_MAX];
size_t gpg_pubkey_where_len;

void
setup(){
       char xdg_home[PATH_MAX];
       setenv("GNUPGHOME", "/home/ganon/.gnupg", 1);           // secret keys + agent

       gpgme_ctx_t ctx;
       gpgme_check_version(NULL);
       gpgme_set_protocol(NULL, GPGME_PROTOCOL_OpenPGP);
       gpg_error_t err = gpgme_new(&ctx);
       if (err != GPG_ERR_NO_ERROR) {
           fprintf(stderr, "gpgme_new failed: %s\n", gpgme_strerror(err));
           return;
       }
       printf("Context created OK: %p\n", (void*)ctx);  // Should print a valid pointer

       gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
       printf("Protocol set OK\n");

       xdg_where_data(xdg_home);
       if(PATH_MAX - strlen(xdg_home) < 4){
              printf("Error: XDG data path too long: cannot get xdg_data_home\n");
              return;
       } else strncat(xdg_home, "fmsg", 5);

       gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OpenPGP, NULL, xdg_home);   // ← only public keys here
}
// Functions utils

int
gpg_encrypt_and_sign(const char* plaintext, const char* key_id, uint16_t n, const char* recipients[n],
              char** out_endbuf, size_t* out_sizendbuf){

       *out_endbuf = NULL;
       *out_sizendbuf = 0;

       FILE* fout = open_memstream(out_endbuf, out_sizendbuf);
       if (!fout) {
              perror("open_memstream");
              return -1;
       }

       gpgme_error_t err;
       gpgme_ctx_t ctx;
       gpgme_data_t in = NULL, out = NULL;
       gpgme_key_t signer_key = NULL;

       // We need n+1 entries: recipients + terminating NULL
       gpgme_key_t recp_keys[n + 1];
       memset(recp_keys, 0, sizeof(recp_keys));  // ← VERY IMPORTANT

       setlocale(LC_ALL, "");
       gpgme_check_version(NULL);
       gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));

       err = gpgme_new(&ctx);
       return_if_err(err,-1);

       gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
       gpgme_set_armor(ctx, GPG_USING_ARMOR);

       // Load recipient keys
       int valid_recipients = 0;
       for (uint16_t i = 0; i < n && recipients[i]; i++) {
              err = gpgme_get_key(ctx, recipients[i], &recp_keys[i], 0);
              if (err != GPG_ERR_NO_ERROR) {
                     fprintf(stderr, "Recipient key not found: %s (%s)\n",
                                   recipients[i], gpgme_strerror(err));
                     recp_keys[i] = NULL;
                     continue;
              }
              if (!recp_keys[i]->can_encrypt) {
                     fprintf(stderr, "Key %s cannot encrypt\n", recipients[i]);
                     gpgme_key_unref(recp_keys[i]);
                     recp_keys[i] = NULL;
                     continue;
              }
              valid_recipients++;
       }

       if (valid_recipients == 0) {
              fprintf(stderr, "No valid recipient keys\n");
              fclose(fout);
              gpgme_release(ctx);
              return -1;
       }

       /* Last entry must be NULL */
       recp_keys[valid_recipients] = NULL;

       err = gpgme_get_key(ctx, key_id, &signer_key, 1); return_if_err(err,-1);
       err = gpgme_signers_add(ctx, signer_key);         return_if_err(err,-1);

       /* Data buffers */
       err = gpgme_data_new_from_mem(&in, plaintext, strlen(plaintext), 1); return_if_err(err,-1);
       err = gpgme_data_new(&out); return_if_err(err,-1);

       err = gpgme_op_encrypt_sign(ctx, recp_keys, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
       if (err != GPG_ERR_NO_ERROR) {
              fprintf(stderr, "gpgme_op_encrypt_sign failed: %s: %s\n",
                            gpgme_strsource(err), gpgme_strerror(err));
       }

       if (err == GPG_ERR_NO_ERROR) {
              char *buf;
              size_t size;
              buf = gpgme_data_release_and_get_mem(out, &size);
              // gpgme_data_release_and_get_mem NULLs out → out becomes invalid
              out = NULL;

              if (buf) {
                     // Some versions append \0 already, but be safe
                     if (size == 0 || buf[size-1] != '\0')
                            buf = realloc(buf, size + 1), buf[size] = '\0';

                     fprintf(fout, "%s", buf);
                     gpgme_free(buf);
              }
       }

       /* Cleanup */
       if (in)  gpgme_data_release(in);
       if (out) gpgme_data_release(out);
       if (signer_key) gpgme_key_unref(signer_key);

       for (int i = 0; i < n; i++) {
              if (recp_keys[i])
                     gpgme_key_unref(recp_keys[i]);
       }

       gpgme_release(ctx);
       fclose(fout);  // ← this flushes to *out_endbuf / *out_sizendbuf

       return (err == GPG_ERR_NO_ERROR) ? 0 : -1;
}

decrypt_verify_result_t decrypt_and_verify_gpgme(const char *ciphertext)
{
       decrypt_verify_result_t result = {0};
       gpgme_ctx_t ctx;
       gpgme_data_t in, out;
       gpgme_error_t err;

       setlocale(LC_ALL, "");
       gpgme_check_version(NULL);

       // ---- Create context ----
       err = gpgme_new(&ctx);
       return_if_err(err,result);

       gpgme_set_armor(ctx, GPG_USING_ARMOR);

       // ---- Create data buffers ----
       err = gpgme_data_new_from_mem(&in, ciphertext, strlen(ciphertext), 0);
       if (err) {
              fprintf(stderr, "gpgme_data_new_from_mem: %s\n", gpgme_strerror(err));
              gpgme_release(ctx);
              return result;
       }

       err = gpgme_data_new(&out);
       if (err) {
              fprintf(stderr, "gpgme_data_new: %s\n", gpgme_strerror(err));
              gpgme_data_release(in);
              gpgme_release(ctx);
              return result;
       }

       // ---- Decrypt+Verify ----
       err = gpgme_op_decrypt_verify(ctx, in, out);
       if (err) {
              fprintf(stderr, "gpgme_op_decrypt_verify: %s\n", gpgme_strerror(err));
              goto cleanup;
       }

       // ---- Extract decrypted text ----
       size_t out_size;
       char *buf = gpgme_data_release_and_get_mem(out, &out_size);
       out = NULL;

       if (buf) {
              result.plaintext = calloc(1, out_size + 1);
              memcpy(result.plaintext, buf, out_size);
              gpgme_free(buf);
       }

       // ---- Examine signature results ----
       gpgme_signature_t sig = gpgme_op_verify_result(ctx)->signatures;

       if (!sig) {
              printf("no signature found\n");
              result.signature_valid = -1; // no signature found
       } else {
              // first signature only
              result.signer_fingerprint = strdup(sig->fpr ? sig->fpr : "");
              if (sig->status == GPG_ERR_NO_ERROR
              && (sig->summary & GPGME_SIGSUM_VALID)) {
                     result.signature_valid = 1;
              } else {
                     result.signature_valid = 0;
              }
       }

cleanup:
       if (in) gpgme_data_release(in);
       if (out) gpgme_data_release(out);
       gpgme_release(ctx);

       return result;
}


char* export_public_key(char *fpr)
{
       gpgme_error_t err;
       gpgme_ctx_t ctx;
       gpgme_data_t dh = NULL;
       char *buf = NULL;
       size_t len;

       setlocale(LC_ALL, "");
       gpgme_check_version(NULL);

       if ((err = gpgme_new(&ctx)) != GPG_ERR_NO_ERROR) goto leave;
       gpgme_set_armor(ctx, GPG_USING_ARMOR);

       if ((err = gpgme_data_new(&dh)) != GPG_ERR_NO_ERROR) goto leave;

       if ((err = gpgme_op_export(ctx, fpr, GPGME_EXPORT_MODE_MINIMAL, dh)) != GPG_ERR_NO_ERROR)
              goto leave;

       buf = gpgme_data_release_and_get_mem(dh, &len);
       dh = NULL;  // ownership transferred
       if (buf) {
              buf = realloc(buf, len + 1);
              if (buf) buf[len] = '\0';
       }

leave:
       if (dh) gpgme_data_release(dh);
       if (ctx) gpgme_release(ctx);
       if (err != GPG_ERR_NO_ERROR) {
              if (buf) { gpgme_free(buf); buf = NULL; }
              fprintf(stderr, "GPGME error: %s\n", gpgme_strerror(err));
       }
       return buf;
}

//call this when you want to choose between identities
char* userinput_identity_can_encrypt(void)
{
       gpgme_ctx_t ctx;
       gpgme_key_t key;
#define MAX_KEYS 256
       char uids[MAX_KEYS][128];
       gpgme_check_version(NULL);
       gpgme_error_t err = gpgme_new(&ctx);
       return_if_err(err,NULL);
       gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
       gpgme_op_keylist_start(ctx, NULL, 1);   // 1 = secret keys only

       printf("Choose your identity:\n");
       int choice = 1;
       while (gpgme_op_keylist_next(ctx, &key) == GPG_ERR_NO_ERROR) {
              const char *name    = "???";
              const char *email   = "";
              char *comment = "";
              const char *keyid   = key->subkeys ? key->subkeys->keyid : "???";

              if (key->uids && key->uids->uid) {
                     char *uid = strdup(key->uids->uid);           // make copy to modify
                     char *lt  = strchr(uid, '<');
                     char *gt  = lt ? strchr(lt + 1, '>') : NULL;

                     if (lt && gt) {
                            *lt = '\0'; *gt = '\0';
                            email = lt + 1;

                            char *par = strrchr(uid, '(');
                            if (par && par < lt) {
                                   *par = '\0';
                                   comment = par + 1;
                                   comment[strlen(comment)-1] = '\0';
                            }
                            name = uid;
                     } else {
                            name = uid;
                     }

                     printf("  %d. %s <%s>  (%s)%s\n", choice,
                                   name, email, keyid,
                                   comment[0] ? "  " : "");
                     memmove(uids[choice-1],keyid,strlen(keyid));
                     free(uid);
              } else {
                     printf("  %d. <no name>  (%s)\n", choice, keyid);
              }

              choice++;
              gpgme_key_unref(key);
       }

       gpgme_op_keylist_end(ctx);
       gpgme_release(ctx);
       unsigned int selected;
       if(choice == 1){
              fprintf(stderr,"No encryption key available: aborting.\n");\
              return NULL;
       }
       do {
              printf("Select your private key of choosing(1,2,ecc..):");
              scanf("%u",&selected);
              if(selected > choice || selected < 1){
                     printf("Invalid number: selected must be from %d to %d inclusive\n", 1, choice-1);
              }
       } while (selected > choice-1|| selected < 1);
       return strdup(uids[selected-1]);
}

bool is_key_usable(gpgme_key_t key)
{
       if (key->expired || key->revoked || key->disabled)
              return false;
       for (gpgme_user_id_t uid = key->uids; uid; uid = uid->next)
              if (uid->validity >= GPGME_VALIDITY_MARGINAL && !uid->revoked)
                     return true;
       for (gpgme_subkey_t sk = key->subkeys; sk; sk = sk->next)
              if (sk->can_encrypt && !sk->expired && !sk->revoked)
                     return true;

       return false;
}

void xdg_where_data(char xdg_home_data[PATH_MAX]){
       char *dir = getenv("XDG_DATA_HOME");
       if (dir && dir[0]) {
              memmove(xdg_home_data,dir,strlen(dir)+1);
              free(dir);
              return;
       } else if(dir) free(dir);

       // Fallback: OME/.local/share
       bool to_free = false;
       char *home = getenv("HOME");
       if (home){
              to_free = true;
       } else home = "/tmp";   // very unlikely
       snprintf(xdg_home_data, PATH_MAX, "%s/.local/share", home);
       if(to_free) free(home);
}

