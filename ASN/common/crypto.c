#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

/*, Internal ------------------------------------------------------------- */

static void ossl_err(const char *where) {
    unsigned long e;
    fprintf(stderr, "[crypto] error in %s:\n", where);
    while ((e = ERR_get_error()) != 0)
        fprintf(stderr, "  %s\n", ERR_error_string(e, NULL));
}

/*, ECDHE ---------------------------------------------------------------- */

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

int crypto_ecdh_derive_bound(const ecdh_keypair_t *local_kp,
                             const uint8_t        *remote_pubkey,
                             const uint8_t         client_pub[EC_PUBKEY_LEN],
                             const uint8_t         node_pub[EC_PUBKEY_LEN],
                             uint16_t              port,
                             uint8_t               role,
                             aes_key_t            *out_key) {
    if (!local_kp || !local_kp->pkey || !remote_pubkey || !client_pub ||
        !node_pub || !out_key) return -1;

    int           rc     = -1;
    EVP_PKEY     *remote = NULL;
    EVP_PKEY_CTX *dctx   = NULL;
    EVP_KDF      *kdf    = NULL;
    EVP_KDF_CTX  *kctx   = NULL;
    uint8_t       shared[32];
    size_t        shared_len = sizeof(shared);

    remote = import_pubkey(remote_pubkey);
    if (!remote) goto done;

    dctx = EVP_PKEY_CTX_new(local_kp->pkey, NULL);
    if (!dctx || EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, remote) <= 0 ||
        EVP_PKEY_derive(dctx, shared, &shared_len) <= 0) {
        ossl_err("ecdh derive (bound)"); goto done;
    }

    /* info = "anon-sec-net-v1" ||
     * client_pub || node_pub || port(2B BE) || role(1B). Fixed-length
     * fields throughout (EC_PUBKEY_LEN is constant, port/role are fixed
     * width), so this concatenation is unambiguous, no length-prefix
     * needed to prevent a boundary-shifting collision between fields. */
    static const uint8_t salt[32] = {0};
    static const char    label[]  = "anon-sec-net-v1";
    uint8_t info[sizeof(label) - 1 + EC_PUBKEY_LEN + EC_PUBKEY_LEN + 2 + 1];
    size_t  off = 0;
    memcpy(info + off, label, sizeof(label) - 1); off += sizeof(label) - 1;
    memcpy(info + off, client_pub, EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;
    memcpy(info + off, node_pub,   EC_PUBKEY_LEN); off += EC_PUBKEY_LEN;
    info[off++] = (uint8_t)(port >> 8);
    info[off++] = (uint8_t)(port & 0xFF);
    info[off++] = role;

    kdf  = EVP_KDF_fetch(NULL, "HKDF", NULL);
    kctx = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
    if (!kctx) { ossl_err("hkdf ctx (bound)"); goto done; }

    OSSL_PARAM kp[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256",              0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY,   shared,    shared_len   ),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT,  (void*)salt,sizeof(salt)),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO,  info,      sizeof(info) ),
        OSSL_PARAM_END
    };
    if (EVP_KDF_derive(kctx, out_key->key, AES_KEY_LEN, kp) <= 0) {
        ossl_err("hkdf derive (bound)"); goto done;
    }

    rc = 0;
done:
    OPENSSL_cleanse(shared, sizeof(shared));
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

int crypto_pubkey_pin_check(uint16_t port, const uint8_t pubkey[EC_PUBKEY_LEN],
                             const char *pin_dir) {
    if (!pubkey || !pin_dir) return -1;

    /* Report mkdir()'s specific failure cause when it isn't the
     * expected EEXIST, rather than letting it surface only as an opaque
     * pin-store error later with no mention of the directory itself. */
    if (mkdir(pin_dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "[crypto] mkdir(%s) failed: %s\n", pin_dir, strerror(errno));
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/pinned_%u.pub", pin_dir, (unsigned)port);

    uint8_t existing[EC_PUBKEY_LEN];
    if (crypto_pubkey_load(existing, path) == 0) {
        if (crypto_memcmp(existing, pubkey, EC_PUBKEY_LEN) != 0) {
            fprintf(stderr,
                    "[crypto] PIN MISMATCH for port %u, key differs from "
                    "the one pinned on first connection. Rejecting: this is "
                    "what an active MITM substituting its own key looks "
                    "like. Delete %s to re-pin if the node's key legitimately "
                    "changed.\n", (unsigned)port, path);
            return -1;
        }
        return 0;
    }

    /* No existing pin, trust-on-first-use. */
    ecdh_keypair_t tmp = {0};
    memcpy(tmp.pubkey_bytes, pubkey, EC_PUBKEY_LEN);
    if (crypto_pubkey_save(&tmp, path) != 0) {
        fprintf(stderr, "[crypto] pin store failed for port %u (%s)\n",
                (unsigned)port, path);
        return -1;
    }
    return 0;
}

/*, Node identity signing ---------------------------- */

int crypto_sign_keygen(ecdh_keypair_t *kp) {
    /* Same EC/P-256 generation mechanism as crypto_ecdh_keygen(), see
     * crypto.h's comment above crypto_sign_keygen() for why this must
     * not be used interchangeably with an ECDH session keypair despite
     * the identical generation code. */
    return crypto_ecdh_keygen(kp);
}

int crypto_identity_load_or_create(ecdh_keypair_t *kp, const char *path) {
    if (!kp || !path) return -1;
    kp->pkey = NULL;

    FILE *f = fopen(path, "rb");
    if (f) {
        EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        fclose(f);
        if (!pkey) {
            fprintf(stderr, "[crypto] identity key at %s is corrupt/unreadable\n", path);
            return -1;
        }
        size_t pub_len = EC_PUBKEY_LEN;
        if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                             kp->pubkey_bytes, EC_PUBKEY_LEN,
                                             &pub_len)
            || pub_len != EC_PUBKEY_LEN) {
            ossl_err("identity load export pubkey");
            EVP_PKEY_free(pkey);
            return -1;
        }
        kp->pkey = pkey;
        return 0;
    }

    /* No existing identity key, generate one and persist it. This is
     * the ONLY keypair in this codebase meant to survive process
     * restart; every other keygen call in this file is deliberately
     * fresh every time. */
    if (crypto_sign_keygen(kp) != 0) return -1;

    /* open() with O_CREAT|O_EXCL and an explicit mode sets the
     * permissions atomically at creation, unlike a fopen()+chmod()
     * sequence, which would leave the file at the default fopen() mode
     * for the window between creation and chmod(). O_EXCL also rejects
     * a symlink/hardlink planted at this path ahead of time. */
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        fprintf(stderr, "[crypto] cannot create identity key file %s: %s\n",
                path, strerror(errno));
        crypto_ecdh_free(kp);
        return -1;
    }
    FILE *out = fdopen(fd, "wb");
    if (!out) {
        fprintf(stderr, "[crypto] fdopen failed for identity key file %s\n", path);
        close(fd);
        crypto_ecdh_free(kp);
        return -1;
    }
    int ok = PEM_write_PrivateKey(out, kp->pkey, NULL, NULL, 0, NULL, NULL);
    fclose(out);
    if (!ok) {
        ossl_err("identity key save");
        crypto_ecdh_free(kp);
        return -1;
    }
    return 0;
}

int crypto_sign(const ecdh_keypair_t *identity_kp,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t *sig, size_t sig_buf_len) {
    if (!identity_kp || !identity_kp->pkey || !msg || !sig) return -1;

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) { ossl_err("sign ctx"); return -1; }

    int rc = -1;
    size_t sig_len = sig_buf_len;
    if (EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, identity_kp->pkey) <= 0 ||
        EVP_DigestSign(mctx, sig, &sig_len, msg, msg_len) <= 0) {
        ossl_err("sign");
        goto done;
    }
    rc = (int)sig_len;
done:
    EVP_MD_CTX_free(mctx);
    return rc;
}

int crypto_verify(const uint8_t identity_pubkey[EC_PUBKEY_LEN],
                   const uint8_t *msg, size_t msg_len,
                   const uint8_t *sig, size_t sig_len) {
    if (!identity_pubkey || !msg || !sig || sig_len == 0) return -1;

    EVP_PKEY *pkey = import_pubkey(identity_pubkey);
    if (!pkey) return -1;

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx) { ossl_err("verify ctx"); EVP_PKEY_free(pkey); return -1; }

    int rc = -1;
    if (EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        ossl_err("verify init");
        goto done;
    }
    /* EVP_DigestVerify returns 1 on a valid signature, 0 on an invalid
     * one, <0 on a different error, all non-1 outcomes are "reject",
     * not just <0. */
    if (EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len) != 1) {
        rc = -1;
    } else {
        rc = 0;
    }
done:
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return rc;
}

/*, AES-256-GCM ---------------------------------------------------------- */

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

/*, Utilities ------------------------------------------------------------ */

int crypto_memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *p = a, *q = b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= p[i] ^ q[i];
    return diff;
}
