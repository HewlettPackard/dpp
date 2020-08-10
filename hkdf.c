/*
 * Copyright (c) Dan Harkins, 2009, 2016
 *
 *  Copyright holder grants permission for redistribution and use in source 
 *  and binary forms, with or without modification, provided that the 
 *  following conditions are met:
 *     1. Redistribution of source code must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in all source files.
 *     2. Redistribution in binary form must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in the documentation and/or other materials provided with the
 *        distribution.
 *
 *  "DISCLAIMER OF LIABILITY
 *  
 *  THIS SOFTWARE IS PROVIDED BY DAN HARKINS ``AS IS''
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL DAN HARKINS BE LIABLE 
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE."
 *
 * This license and distribution terms cannot be changed. In other words,
 * this code cannot simply be copied and put under another distribution
 * license (including the GNU public license).
 */
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

int
hkdf_extract (const EVP_MD *h,
              unsigned char *salt, int saltlen,
              unsigned char *ikm, int ikmlen,
              unsigned char *prk)               // prklen depnds on h
{
    unsigned char *tweak;
    int prklen, tweaklen;
    HMAC_CTX *ctx;

    prklen = EVP_MD_size(h);
    if ((ctx = HMAC_CTX_new()) == NULL) {
        perror("HMAC_CTX_new()");
        return -1;
    }

    if (!salt || (saltlen == 0)) {
        if ((tweak = (unsigned char *)malloc(prklen)) == NULL) {
            perror("malloc");
            HMAC_CTX_free(ctx);
            return 0;
        }
        memset(tweak, 0, prklen);
        tweaklen = prklen;
    } else {
        tweak = salt;
        tweaklen = saltlen;
    }
    (void)HMAC(h, tweak, tweaklen, ikm, ikmlen, prk, &prklen);
    if (!salt || (saltlen == 0)) {
        free(tweak);
    }
    HMAC_CTX_free(ctx);
    return prklen;
}

int
hkdf_expand (const EVP_MD *h,
             unsigned char *prk, int prklen,    // "at least HashLen octets"
             unsigned char *info, int infolen,
             unsigned char *okm, int okmlen)
{
    HMAC_CTX *ctx;
    unsigned char ctr, *digest;
    int len, digestlen;

    digestlen = EVP_MD_size(h);
    if ((digest = (unsigned char *)malloc(digestlen)) == NULL) {
        perror("malloc");
        return -1;
    }
    if ((ctx = HMAC_CTX_new()) == NULL) {
        perror("HMAC_CTX_new()");
        return -1;
    }

    memset(digest, 0, digestlen);
    digestlen = 0;
    ctr = 0;
    len = 0;
    while (len < okmlen) {
        /*
         * T(0) = all zeros
         * T(n) = HMAC(prk, T(n-1) | info | counter)
         * okm = T(0) | ... | T(n)
         */
        ctr++;
        HMAC_Init_ex(ctx, prk, prklen, h, NULL);
        HMAC_Update(ctx, digest, digestlen);
        if (info && (infolen != 0)) {
            HMAC_Update(ctx, info, infolen);
        }
        HMAC_Update(ctx, &ctr, sizeof(unsigned char));
        HMAC_Final(ctx, digest, &digestlen);
        if ((len + digestlen) > okmlen) {
            memcpy(okm + len, digest, okmlen - len);
        } else {
            memcpy(okm + len, digest, digestlen);
        }
        HMAC_CTX_reset(ctx);
        len += digestlen;
    }
    free(digest);
    HMAC_CTX_free(ctx);

    return okmlen;
}

int
hkdf (const EVP_MD *h, int skip,
      unsigned char *ikm, int ikmlen,
      unsigned char *salt, int saltlen,
      unsigned char *info, int infolen,
      unsigned char *okm, int okmlen)
{
    unsigned char *prk, *tweak, ctr, *digest;
    int len;
    unsigned int digestlen, prklen, tweaklen;
    HMAC_CTX *ctx;

    digestlen = prklen = EVP_MD_size(h);
    if ((digest = (unsigned char *)malloc(digestlen)) == NULL) {
        perror("malloc");
        return 0;
    }
    if ((ctx = HMAC_CTX_new()) == NULL) {
        perror("HMAC_CTX_new()");
        free(digest);
        return 0;
    }
    if (!skip) {
        /*
         * if !skip then do HKDF-extract
         */
        if ((prk = (unsigned char *)malloc(digestlen)) == NULL) {
            free(digest);
            perror("malloc");
            return 0;
        }
        /*
         * if there's no salt then use all zeros
         */
        if (!salt || (saltlen == 0)) {
            if ((tweak = (unsigned char *)malloc(digestlen)) == NULL) {
                free(digest);
                free(prk);
                perror("malloc");
                return 0;
            }
            memset(tweak, 0, digestlen);
            tweaklen = saltlen;
        } else {
            tweak = salt;
            tweaklen = saltlen;
        }
        (void)HMAC(h, tweak, tweaklen, ikm, ikmlen, prk, &prklen);
        if (!salt || (saltlen == 0)) {
            free(tweak);
        }
    } else {
        prk = ikm;
        prklen = ikmlen;
    }
    memset(digest, 0, digestlen);
    digestlen = 0;
    ctr = 0;
    len = 0;
    while (len < okmlen) {
        /*
         * T(0) = all zeros
         * T(n) = HMAC(prk, T(n-1) | info | counter)
         * okm = T(0) | ... | T(n)
         */
        ctr++;
        HMAC_Init_ex(ctx, prk, prklen, h, NULL);
        HMAC_Update(ctx, digest, digestlen);
        if (info && (infolen != 0)) {
            HMAC_Update(ctx, info, infolen);
        }
        HMAC_Update(ctx, &ctr, sizeof(unsigned char));
        HMAC_Final(ctx, digest, &digestlen);
        if ((len + digestlen) > okmlen) {
            memcpy(okm + len, digest, okmlen - len);
        } else {
            memcpy(okm + len, digest, digestlen);
        }
        HMAC_CTX_reset(ctx);
        len += digestlen;
    }
    if (!skip) {
        free(prk);
    }
    free(digest);
    HMAC_CTX_free(ctx);

    return okmlen;
}
