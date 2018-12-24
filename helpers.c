#include "helpers.h"

EVP_MD_CTX *EVP_MD_CTX_new(void)
{
    return (EVP_MD_CTX *)malloc(sizeof(EVP_MD_CTX));
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    free(ctx);
}

HMAC_CTX *HMAC_CTX_new(void)
{
    HMAC_CTX *ctx = (HMAC_CTX *)malloc(sizeof(HMAC_CTX));

    if (ctx != NULL) {
        if (!HMAC_CTX_reset(ctx)) {
            HMAC_CTX_free(ctx);
            return NULL;
        }
        HMAC_CTX_init(ctx);
    }
    return ctx;
}


static void hmac_ctx_cleanup(HMAC_CTX *ctx)
{
    ctx->md = NULL;
    ctx->key_length = 0;
    OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
}


void HMAC_CTX_free(HMAC_CTX *ctx)
{
    if (ctx != NULL) {
        hmac_ctx_cleanup(ctx);
        free(ctx);
    }
}

int HMAC_CTX_reset(HMAC_CTX *ctx)
{
    hmac_ctx_cleanup(ctx);
    ctx->md = NULL;
    return 1;
}

void
ECDSA_SIG_get0(ECDSA_SIG *sig, const BIGNUM **r, const BIGNUM **s)
{
    *r = sig->r;
    *s = sig->s;
    return;
}

void
ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    sig->r = r;
    sig->s = s;
    return;
}

