#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/params.h>

#include <stdio.h>
#include <string.h>

/* -- Internal ------------------------------------------------------------- */

static void ossl_err(const char *where) {
    unsigned long e;
    fprintf(stderr, "[crypto] error in %s:\n", where);
    while ((e = ERR_get_error()) != 0)
        fprintf(stderr, "  %s\n", ERR_error_string(e, NULL));
}

/* -- ECDHE ---------------------------------------------------------------- */

int crypto_ecdh_keygen(ecdh_keypair_t *kp) {
    if (!kp) return -1;
    kp->pkey = NULL;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) { ossl_err("keygen ctx"); return -1; }

    int rc = -1;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        ossl_err("keygen_init"); goto done;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0),
        OSSL_PARAM_END
    };
    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
        ossl_err("keygen set_params"); goto done;
    }
    if (EVP_PKEY_generate(ctx, &kp->pkey) <= 0) {
        ossl_err("keygen generate"); goto done;
    }

    /* Export uncompressed public key (0x04 || x || y = 65 bytes) */
    size_t pub_len = EC_PUBKEY_LEN;
    if (!EVP_PKEY_get_octet_string_param(kp->pkey,
                                         OSSL_PKEY_PARAM_PUB_KEY,
                                         kp->pubkey_bytes,
                                         EC_PUBKEY_LEN,
                                         &pub_len)
        || pub_len != EC_PUBKEY_LEN) {
        ossl_err("keygen export pubkey"); goto done;
    }

    rc = 0;
done:
    EVP_PKEY_CTX_free(ctx);
    if (rc != 0 && kp->pkey) { EVP_PKEY_free(kp->pkey); kp->pkey = NULL; }
    return rc;
}

/* Import 65-byte uncompressed P-256 public key from wire bytes */
static EVP_PKEY *import_pubkey(const uint8_t *raw) {
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)raw, EC_PUBKEY_LEN),
        OSSL_PARAM_END
    };

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) { ossl_err("import ctx"); return NULL; }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        ossl_err("import fromdata");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

int crypto_ecdh_derive(const ecdh_keypair_t *local_kp,
                       const uint8_t        *remote_pubkey,
                       aes_key_t            *out_key) {
    if (!local_kp || !local_kp->pkey || !remote_pubkey || !out_key) return -1;

    int           rc     = -1;
    EVP_PKEY     *remote = NULL;
    EVP_PKEY_CTX *dctx   = NULL;
    EVP_KDF      *kdf    = NULL;
    EVP_KDF_CTX  *kctx   = NULL;
    uint8_t       shared[32];
    size_t        shared_len = sizeof(shared);

    /* Step 1: import remote public key */
    remote = import_pubkey(remote_pubkey);
    if (!remote) goto done;

    /* Step 2: ECDH -> shared secret (x-coordinate of shared point, 32 bytes) */
    dctx = EVP_PKEY_CTX_new(local_kp->pkey, NULL);
    if (!dctx || EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, remote) <= 0 ||
        EVP_PKEY_derive(dctx, shared, &shared_len) <= 0) {
        ossl_err("ecdh derive"); goto done;
    }

    /* Step 3: HKDF-SHA256 shared_secret -> 32-byte AES-256 key
     * Zero salt is safe here: the ECDH shared secret already has
     * high entropy (32 bytes from a P-256 point coordinate).      */
    static const uint8_t salt[32] = {0};
    static const char    info[]   = "anon-sec-net-v1";

    kdf  = EVP_KDF_fetch(NULL, "HKDF", NULL);
    kctx = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
    if (!kctx) { ossl_err("hkdf ctx"); goto done; }

    OSSL_PARAM kp[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256",              0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY,   shared,    shared_len   ),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT,  (void*)salt,sizeof(salt)),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO,  (void*)info,sizeof(info)-1),
        OSSL_PARAM_END
    };
    if (EVP_KDF_derive(kctx, out_key->key, AES_KEY_LEN, kp) <= 0) {
        ossl_err("hkdf derive"); goto done;
    }

    rc = 0;
done:
    OPENSSL_cleanse(shared, sizeof(shared));  /* wipe secret from stack */
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(remote);
    return rc;
}

void crypto_ecdh_free(ecdh_keypair_t *kp) {
    if (kp && kp->pkey) {
        EVP_PKEY_free(kp->pkey);
        kp->pkey = NULL;
    }
}

int crypto_pubkey_save(const ecdh_keypair_t *kp, const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) { perror("pubkey_save"); return -1; }
    int ok = ((int)fwrite(kp->pubkey_bytes, 1, EC_PUBKEY_LEN, f) == EC_PUBKEY_LEN);
    fclose(f);
    return ok ? 0 : -1;
}

int crypto_pubkey_load(uint8_t out[EC_PUBKEY_LEN], const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("pubkey_load"); return -1; }
    int ok = ((int)fread(out, 1, EC_PUBKEY_LEN, f) == EC_PUBKEY_LEN);
    fclose(f);
    return ok ? 0 : -1;
}

/* -- AES-256-GCM ---------------------------------------------------------- */

int crypto_aes_encrypt(const aes_key_t *key,
                       const uint8_t   *plaintext,  size_t plaintext_len,
                       uint8_t         *out,        size_t out_size) {
    if (!key || !plaintext || !out) return -1;
    if (out_size < plaintext_len + GCM_OVERHEAD) {
        fprintf(stderr, "[crypto] encrypt: output buffer too small\n");
        return -1;
    }

    uint8_t *nonce      = out;
    uint8_t *ciphertext = out + GCM_NONCE_LEN;
    uint8_t *tag        = out + GCM_NONCE_LEN + plaintext_len;

    if (RAND_bytes(nonce, GCM_NONCE_LEN) != 1) {
        ossl_err("encrypt RAND_bytes"); return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { ossl_err("encrypt ctx"); return -1; }

    int ret = -1, len = 0, flen = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)    != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                             GCM_NONCE_LEN, NULL)                       != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key->key, nonce)            != 1) goto done;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len,
                          plaintext, (int)plaintext_len)                != 1) goto done;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &flen)               != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                             GCM_TAG_LEN, tag)                          != 1) goto done;

    ret = (int)(GCM_NONCE_LEN + plaintext_len + GCM_TAG_LEN);
done:
    EVP_CIPHER_CTX_free(ctx);
    if (ret < 0) ossl_err("encrypt");
    return ret;
}

int crypto_aes_decrypt(const aes_key_t *key,
                       const uint8_t   *in,  size_t in_len,
                       uint8_t         *out, size_t out_size) {
    if (!key || !in || !out) return -1;
    if (in_len < (size_t)GCM_OVERHEAD) {
        fprintf(stderr, "[crypto] decrypt: input too short\n"); return -1;
    }

    size_t         pt_len     = in_len - GCM_OVERHEAD;
    const uint8_t *nonce      = in;
    const uint8_t *ciphertext = in + GCM_NONCE_LEN;
    const uint8_t *tag        = in + in_len - GCM_TAG_LEN;

    if (out_size < pt_len) {
        fprintf(stderr, "[crypto] decrypt: output buffer too small\n"); return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { ossl_err("decrypt ctx"); return -1; }

    int ret = -1, len = 0, flen = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)    != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                             GCM_NONCE_LEN, NULL)                       != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key->key, nonce)            != 1) goto done;
    if (EVP_DecryptUpdate(ctx, out, &len,
                          ciphertext, (int)pt_len)                      != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             GCM_TAG_LEN, (void *)tag)                  != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, out + len, &flen)                      <= 0) {
        goto done;
    }

    ret = (int)pt_len;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* -- Utilities ------------------------------------------------------------ */

void crypto_hexdump(const char *label, const uint8_t *data, size_t len) {
    fprintf(stderr, "[%s] %zu bytes:\n  ", label, len);
    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, "%02x", data[i]);
        if ((i+1) % 32 == 0 && i+1 < len) fprintf(stderr, "\n  ");
        else if ((i+1) %  8 == 0 && i+1 < len) fprintf(stderr, "  ");
    }
    fprintf(stderr, "\n");
}

int crypto_memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *p = a, *q = b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= p[i] ^ q[i];
    return diff;
}
