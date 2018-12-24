#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ecdsa.h>

EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *);

HMAC_CTX *HMAC_CTX_new();
void HMAC_CTX_free(HMAC_CTX *);
int HMAC_CTX_reset(HMAC_CTX *);

void ECDSA_SIG_get0(ECDSA_SIG *, const BIGNUM **, const BIGNUM **);
void ECDSA_SIG_set0(ECDSA_SIG *, BIGNUM *, BIGNUM *);

