/*
 * (c) Copyright 2016-2020 Hewlett Packard Enterprise Development LP
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include "jsmn.h"
#ifdef FREEBSD
#include "helpers.h"
#endif  /* FREEBSD */

static int skip_object(jsmntok_t *t);
static int skip_array(jsmntok_t *t);
static int skip_string(jsmntok_t *t);
static int skip_primitive(jsmntok_t *t);

#define BIGGEST_POSSIBLE_SIGNATURE      140

static int
skip_single (jsmntok_t *t)
{
    int i;
    
    switch (TOKTYPE(t)) {
        case JSMN_OBJECT:
            i = skip_object(t);
            break;
        case JSMN_ARRAY:
            i = skip_array(t);
            break;
        case JSMN_STRING:
            i = skip_string(t);
            break;
        case JSMN_PRIMITIVE:
            i = skip_primitive(t);
            break;
        default:
            i = 1;
    }
    return i;
}

static int
skip_string (jsmntok_t *t)
{
    return 1;
}

static int
skip_primitive (jsmntok_t *t)
{
    return 1;
}

static int
skip_object (jsmntok_t *t)
{
    int i, j;

    i = 0;
    /*
     * an object is followed by another token and it's attributes...
     */
    for (j = 0; j < t->size; j++) {
        i += skip_single(t+1);
        i += skip_single(t+1+i);
    }
    return i+1;
}

int
skip_array (jsmntok_t *t)
{
    int i, j;

    i = 0;
    /*
     * an array is a series of tokens
     */
    for (j = 0; j < t->size; j++) {
        i += skip_single(t+1);
    }
    return i+1;
}

static int
find_token (jsmntok_t *toks, int *n, int ntoks, char *buffer, char *str)
{
    int i, num;
    jsmntok_t *tok;
    
    num = *n;
    for (i = 0; i < ntoks; i++) {
        tok = &toks[num];
        /*
         * we should be looking at a token of type string
         */
        if (TOKTYPE(tok) != JSMN_STRING) {
            return -1;
        }
        /*
         * see if it's the one we want
         */
        if (memcmp(str, buffer + TOKSTART(tok), strlen(str)) == 0) {
            *n = num;
            return num;
        }
        /*
         * it's not the one we want so skip over its attribute(s)
         */
        num++;
        tok = tok + 1;
        switch (TOKTYPE(tok)) {
            case JSMN_OBJECT:
                num += skip_object(tok);
                break;
            case JSMN_ARRAY:
                num += skip_array(tok);
                break;
            case JSMN_STRING:
                num += skip_string(tok);
                break;
            case JSMN_PRIMITIVE:
                num += skip_primitive(tok);
                break;
            default:
                break;
        }
    }
    return -1;
}

int
get_json_data (char *buf, int buflen, char **start, char **end,
               const int nlab, ...)
{
    va_list labs;
    char *lab;
    int i =0, ntoks, numlab = nlab, ret = -1;
    jsmntok_t *tok, *toks;
    jsmn_parser p;
    
    if (!nlab) {
        return 0;
    }
    jsmn_init(&p);
    if ((ntoks = jsmn_parse(&p, buf, buflen, NULL, 200)) == 0) {
        return 0;
    }
    if ((toks = (jsmntok_t *)malloc(ntoks * sizeof(jsmntok_t))) == NULL) {
        return -1;
    }
    jsmn_init(&p);
    if ((ntoks = jsmn_parse(&p, buf, buflen, toks, ntoks)) == 0) {
        goto fin;
    }
    tok = &toks[0];
    if (TOKTYPE(tok) != JSMN_OBJECT) {
        goto fin;
    }
    /*
     * run through all of the keywords searching through the JSON
     */
    va_start(labs, nlab);
    while (numlab) {
        lab = (char *)va_arg(labs, char *);
        i++;
        if (find_token(toks, &i, ntoks, buf, lab) < 1) {
            goto fin;
        }
        i++;
        tok = &toks[i];
        ntoks = tok->size;
        numlab--;
    }
    va_end(labs);
    /*
     * we have found what we're looking for!
     */
    switch (TOKTYPE(tok)) {
        case JSMN_OBJECT:
        case JSMN_ARRAY:
            *start = buf + TOKSTART(tok) + 1;
            *end = *start + TOKLEN(tok) - 2;
            ret = tok->size;
            break;
        case JSMN_PRIMITIVE:
        case JSMN_STRING:
            *start = buf + TOKSTART(tok);
            *end = *start + TOKLEN(tok);
            ret = 1;
            break;
        default:
            break;
    }
fin:
    free(toks);
    return ret;
}

int
base64urlencode (unsigned char *burl, unsigned char *data, int len)
{
    int octets, i;

    /*
     * b64 the data, replace the non-URL safe characters, and get rid of padding
     */
    octets = EVP_EncodeBlock(burl, data, len);
    for (i = 0; i < octets; i++) {
        if (burl[i] == '+') {
            burl[i] = '-';
        } else if (burl[i] == '/') {
            burl[i] = '_';
        }
    }
    while (burl[octets-1] == '=') {
        burl[octets-1] = '\0';
        octets--;
    }
    return octets;
}

int
base64urldecode (unsigned char *data, unsigned char *burl, int len)
{
    int res, pad, i;
    unsigned char *b64, *unb64;

    /*
     * allocate bigger buffers to b64 decode
     */
    pad = 0;
    switch (len%4) {
        case 2:
            pad = 2;
            break;
        case 3:
            pad = 1;
            break;
        case 0:
            break;
        default:
            return -1;
    }
    if ((b64 = (unsigned char *)malloc(len + pad)) == NULL) {
        return -1;
    }
    if ((unb64 = (unsigned char *)malloc(len)) == NULL) {
        free(b64);
        return -1;
    }
    memset(b64, '=', len + pad);
    memcpy(b64, burl, len);
    /*
     * make it URL unsafe again
     */
    for (i = 0; i < len; i++) {
        if (b64[i] == '-') {
            b64[i] = '+';
        } else if (b64[i] == '_') {
            b64[i] = '/';
        }
    }
    /*
     * b64 decode the data now and copy it to the buffer
     */
    res = EVP_DecodeBlock(unb64, b64, len + pad);
    memcpy(data, unb64, res - pad);
    free(b64);
    free(unb64);

    return res - pad;
}

int
base64urlencode_verbose (unsigned char *burl, unsigned char *data, int len)
{
    int octets, i;

    /*
     * b64 the data, replace the non-URL safe characters, and get rid of padding
     */
    octets = EVP_EncodeBlock(burl, data, len);
    printf("b64 encoded %d to get %d\n", len, octets);
    for (i = 0; i < octets; i++) {
        printf("%c", burl[i]);
    }
    printf("\n");
    for (i = 0; i < octets; i++) {
        if (burl[i] == '+') {
            burl[i] = '-';
        } else if (burl[i] == '/') {
            burl[i] = '_';
        }
    }
    while (burl[octets-1] == '=') {
        printf("removing a '=' at %d\n", octets-1);
        burl[octets-1] = '\0';
        octets--;
    }
    printf("returning %d octets\n", octets);
    return octets;
}

int
base64urldecode_verbose (unsigned char *data, unsigned char *burl, int len)
{
    int res, pad, i;
    unsigned char *b64, *unb64;

    /*
     * allocate a, possibly, bigger buffer to b64 decode
     */
    pad = 0;
    switch (len%4) {
        case 2:
            pad = 2;
            break;
        case 3:
            pad = 1;
            break;
        case 0:
            break;
        default:
            return -1;
    }
    printf("data is %d, adding %d bytes of pad to decode data\n", len, pad);
    if ((b64 = (unsigned char *)malloc(len + pad)) == NULL) {
        return -1;
    }
    if ((unb64 = (unsigned char *)malloc(len)) == NULL) {
        free(b64);
        return -1;
    }
    memset(b64, '=', len + pad);
    memcpy(b64, burl, len);
    /*
     * make it URL unsafe again
     */
    for (i = 0; i < len; i++) {
        if (b64[i] == '-') {
            b64[i] = '+';
        } else if (b64[i] == '_') {
            b64[i] = '/';
        }
    }
    /*
     * b64 decode the data now
     */
    for (i = 0; i < (len + pad); i++) {
        printf("%c", b64[i]);
    }
    printf("\n");
    res = EVP_DecodeBlock(unb64, b64, len + pad);
    printf("b64 decoded %d to get %d\n", len + pad, res);
    memcpy(data, unb64, res - pad);
    free(b64);
    free(unb64);

    return res - pad;
}

int
get_kid_from_point (unsigned char *kid, const EC_GROUP *group, const EC_POINT *pt, BN_CTX *bnctx)
{
    BIGNUM *x = NULL, *y = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int burllen = -1, bnlen, nid, offset;
    unsigned char *bn = NULL, *ptr;
    
    if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
        ((mdctx = EVP_MD_CTX_new()) == NULL)) {
        goto fin;
    }
    nid = EC_GROUP_get_curve_name(group);
    switch (nid) {
        case NID_X9_62_prime256v1:
#ifdef HAS_BRAINPOOL
        case NID_brainpoolP256r1:
#endif  /* HAS_BRAINPOOL */
            bnlen = 32;
            break;
        case NID_secp384r1:
#ifdef HAS_BRAINPOOL
        case NID_brainpoolP384r1:
#endif  /* HAS_BRAINPOOL */
            bnlen = 48;
            break;
        case NID_secp521r1:
            bnlen = 66;
            break;
#ifdef HAS_BRAINPOOL
        case NID_brainpoolP512r1:
            bnlen = 64;
            break;
#endif  /* HAS_BRAINPOOL */
        default:
            goto fin;
    }
    /*
     * get the x- and y-coordinates of the point
     */
    if (!EC_POINT_get_affine_coordinates_GFp(group, pt, x, y, bnctx)) {
        goto fin;
    }

    /*
     * then make it "uncompressed form"....
     */
    if ((bn = (unsigned char *)malloc(2*bnlen + 1)) == NULL) {
        goto fin;
    }
    memset(bn, 0, (2*bnlen + 1));
    bn[0] = 0x04;
    ptr = &bn[1];
    offset = bnlen - BN_num_bytes(x);
    BN_bn2bin(x, ptr + offset);
    ptr = &bn[1+bnlen];
    offset = bnlen - BN_num_bytes(y);
    BN_bn2bin(y, ptr + offset);
    /*
     * hash it all up with SHA256
     */
    EVP_DigestInit(mdctx, EVP_sha256());
    EVP_DigestUpdate(mdctx, bn, 2*bnlen + 1);
    EVP_DigestFinal(mdctx, digest, &mdlen);
    /*
     * and the kid is the base64url of that hash
     */
    if ((burllen = base64urlencode(kid, digest, mdlen)) < 0) {
        goto fin;
    }
    kid[burllen] = '\0';

 fin:
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
    if (bn != NULL) {
        free(bn);
    }
    if (mdctx != NULL) {
        EVP_MD_CTX_free(mdctx);
    }

    return burllen;
}

int
generate_connector (unsigned char *connector, int len, EC_GROUP *group, EC_POINT *netackey,
                    char *role, EC_KEY *signkey, BN_CTX *bnctx)
{
    unsigned char kid[2*SHA256_DIGEST_LENGTH];
    char buf[1024];
    unsigned char burlx[256], burly[256], *bn = NULL;
    unsigned char digest[SHA512_DIGEST_LENGTH], sig[BIGGEST_POSSIBLE_SIGNATURE];
    int nid, primelen, burllen, bnlen, offset, buflen, sofar = 0;
    unsigned int siglen;
    EVP_MD_CTX *mdctx = NULL;
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
    BIGNUM *x = NULL, *y = NULL, *prime = NULL, *r = NULL, *s = NULL;
    BIO *bio = NULL;
    const EC_POINT *signpub;
    const EC_GROUP *signgroup;
    ECDSA_SIG *ecsig;
    time_t t;
    struct tm *bdt;
    

    if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
        ((prime = BN_new()) == NULL) || ((bio = BIO_new(BIO_s_mem())) == NULL)) {
        goto fail;
    }

    /*
     * get the kid of the signing key and the group of the net access key
     */
    if (((signpub = EC_KEY_get0_public_key(signkey)) == NULL) ||
        ((signgroup = EC_KEY_get0_group(signkey)) == NULL) ||
        !EC_GROUP_get_curve_GFp(group, prime, NULL, NULL, bnctx)) {
        goto fail;
    }
    if (get_kid_from_point(kid, (EC_GROUP *)signgroup, (EC_POINT *)signpub, bnctx) < 0) {
        goto fail;
    }

    /*
     * construct a JWS Protected Header and b64url it into the
     * first part of the connector
     */
    nid = EC_GROUP_get_curve_name(signgroup);
    buflen = snprintf(buf, sizeof(buf),
                      "{\"typ\":\"dppCon\",\"kid\":\"%s\",\"alg\":\"%s\"}", kid,
#ifdef HAS_BRAINPOOL
                      nid == NID_X9_62_prime256v1 ? "ES256" : \
                      nid == NID_secp384r1 ? "ES384" : \
                      nid == NID_secp521r1 ? "ES512" : \
                      nid == NID_brainpoolP256r1 ? "BS256" : \
                      nid == NID_brainpoolP384r1 ? "BS384" : \
                      nid == NID_brainpoolP512r1 ? "BS512" : "unknown");
#else
                      nid == NID_X9_62_prime256v1 ? "ES256" : \
                      nid == NID_secp384r1 ? "ES384" : \
                      nid == NID_secp521r1 ? "ES512" : "unknown");
#endif  /* HAS_BRAINPOOL */
    
    if ((sofar = base64urlencode(connector, (unsigned char *)buf, buflen)) < 0) {
        goto fail;
    }
    connector[sofar++] = '.';

    /*
     * construct the connector body object
     *
     * first, b64url encode the x- and y- coordinates of the network access key
     */
    if (!EC_POINT_get_affine_coordinates_GFp(group, netackey, x, y, bnctx)) {
        goto fail;
    }
    bnlen = BN_num_bytes(prime);
    if ((bn = (unsigned char *)malloc(bnlen)) == NULL) {
        goto fail;
    }
    memset(bn, 0, bnlen);
    offset = bnlen - BN_num_bytes(x);
    BN_bn2bin(x, bn + offset);
    if ((burllen = base64urlencode(burlx, bn, bnlen)) < 0) {
        goto fail;
    }
    burlx[burllen] = '\0';

    memset(bn, 0, bnlen);
    offset = bnlen - BN_num_bytes(y);
    BN_bn2bin(y, bn + offset);
    if ((burllen = base64urlencode(burly, bn, bnlen)) < 0) {
        goto fail;
    }
    burly[burllen] = '\0';

    /*
     * then generate a kid for the netackey
     */
    if (get_kid_from_point(kid, group, netackey, bnctx) < 0) {
        goto fail;
    }

   /*
    * get the current time so we can make the connector be good for 1 year
    */
    t = time(NULL);
    bdt = gmtime(&t);
    /*
     * generate the connector body (the JWS Payload)
     */
    nid = EC_GROUP_get_curve_name(group);
    buflen = snprintf(buf, sizeof(buf),
                      "{\"groups\":[{\"groupId\":\"interop\",\"netRole\":\"%s\"}],"
                      "\"netAccessKey\":{\"kty\":\"EC\",\"crv\":\"%s\",\"x\":\"%s\",\"y\":\"%s\","
                      "\"kid\":\"%s\"},\"expiry\":\"%04d-%02d-%02dT%02d:%02d:%02d\"}", role, 
#ifdef HAS_BRAINPOOL
                      nid == NID_X9_62_prime256v1 ? "P-256" : \
                      nid == NID_secp384r1 ? "P-384" : \
                      nid == NID_secp521r1 ? "P-521" : \
                      nid == NID_brainpoolP256r1 ? "BP-256" : \
                      nid == NID_brainpoolP384r1 ? "BP-384" : \
                      nid == NID_brainpoolP512r1 ? "BP-512" : "unknown",
#else
                      nid == NID_X9_62_prime256v1 ? "P-256" : \
                      nid == NID_secp384r1 ? "P-384" : \
                      nid == NID_secp521r1 ? "P-521" : "unknown",
#endif  /* HAS_BRAINPOOL */
                      burlx, burly, kid,
                      bdt->tm_year+1901, bdt->tm_mon, bdt->tm_mday,
                      bdt->tm_hour, bdt->tm_min, bdt->tm_sec);
    if ((burllen = base64urlencode(connector+sofar, (unsigned char *)buf, buflen)) < 0) {
        goto fail;
    }
    sofar += burllen;
    /*
     * calculate the signature on the connector so far
     */
    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        goto fail;
    }

    nid = EC_GROUP_get_curve_name(signgroup);
    switch (nid) {
        case NID_X9_62_prime256v1:
#ifdef HAS_BRAINPOOL
        case NID_brainpoolP256r1:
#endif  /* HAS_BRAINPOOL */
            EVP_DigestInit(mdctx, EVP_sha256());
            primelen = 32;
            break;
        case NID_secp384r1:
#ifdef HAS_BRAINPOOL
        case NID_brainpoolP384r1:
#endif  /* HAS_BRAINPOOL */
            EVP_DigestInit(mdctx, EVP_sha384());
            primelen = 48;
            break;
        case NID_secp521r1:
            EVP_DigestInit(mdctx, EVP_sha512());
            primelen = 66;
            break;
#ifdef HAS_BRAINPOOL
        case NID_brainpoolP512r1:
            EVP_DigestInit(mdctx, EVP_sha512());
            primelen = 64;
            break;
#endif  /* HAS_BRAINPOOL */
        default:
            primelen = 0;
            goto fail;
    }
    EVP_DigestUpdate(mdctx, connector, sofar);
    EVP_DigestFinal(mdctx, digest, &mdlen);

    if ((ecsig = ECDSA_do_sign_ex(digest, mdlen, NULL, NULL, signkey)) == NULL) {
        goto fail;
    }
    ECDSA_SIG_get0(ecsig, (const BIGNUM **)&r, (const BIGNUM **)&s);
    
    memset(sig, 0, BIGGEST_POSSIBLE_SIGNATURE);
    offset = primelen - BN_num_bytes(r);
    BN_bn2bin(r, sig + offset);
    offset = primelen - BN_num_bytes(s);
    BN_bn2bin(s, sig + primelen + offset);
    siglen = primelen * 2;

    /*
     * add the separator and then add the signature
     */
    connector[sofar++] = '.';
    if ((burllen = base64urlencode(connector+sofar, sig, siglen)) < 0) {
        goto fail;
    }
    sofar += burllen;

    if (0) {
fail:
        sofar = -1;
    }
    if (bio != NULL) {
        BIO_free(bio);
    }
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
    if (prime != NULL) {
        BN_free(prime);
    }
    if (bn != NULL) {
        free(bn);
    }
    return sofar;
}

int
validate_connector (unsigned char *connector, int len, EC_KEY *signkey, BN_CTX *bnctx)
{
    EVP_MD_CTX *mdctx = NULL;
    unsigned int mdlen;
    unsigned char *dot1, *dot2, sig[3*SHA512_DIGEST_LENGTH], digest[SHA512_DIGEST_LENGTH];
    const EC_GROUP *signgroup;
    BIGNUM *r = NULL, *s = NULL;
    int nid, siglen, diglen, ret = -1, primelen;
    ECDSA_SIG *ecsig = NULL;

    if (((r = BN_new()) == NULL) || ((s = BN_new()) == NULL) ||
        ((ecsig = ECDSA_SIG_new()) == NULL)) {
        goto fail;
    }
    if (((dot1 = (unsigned char *)strstr((char *)connector, ".")) == NULL) ||
        ((dot2 = (unsigned char *)strstr((char *)dot1+1, ".")) == NULL)) {
        goto fail;
    }
    if ((signgroup = EC_KEY_get0_group(signkey)) == NULL) {
        goto fail;
    }
    
    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        goto fail;
    }

    diglen = (int)(dot2 - connector);
    nid = EC_GROUP_get_curve_name(signgroup);
    switch (nid) {
        case NID_X9_62_prime256v1:
#ifdef HAS_BRAINPOOL
        case NID_brainpoolP256r1:
#endif  /* HAS_BRAINPOOL */
            EVP_DigestInit(mdctx, EVP_sha256());
            primelen = 32;
            break;
        case NID_secp384r1:
#ifdef HAS_BRAINPOOL
        case NID_brainpoolP384r1:
#endif  /* HAS_BRAINPOOL */
            EVP_DigestInit(mdctx, EVP_sha384());
            primelen = 48;
            break;
        case NID_secp521r1:
            EVP_DigestInit(mdctx, EVP_sha512());
            primelen = 66;
            break;
#ifdef HAS_BRAINPOOL
        case NID_brainpoolP512r1:
            EVP_DigestInit(mdctx, EVP_sha512());
            primelen = 64;
            break;
#endif  /* HAS_BRAINPOOL */
        default:
            primelen = 0;
            goto fail;
    }
    EVP_DigestUpdate(mdctx, connector, diglen);
    EVP_DigestFinal(mdctx, digest, &mdlen);

    dot2++;     // skip over '.'

    siglen = base64urldecode(sig, dot2, len - (int)(dot2 - connector));

    if (siglen != (2 * primelen)) {
        goto fail;
    }
    BN_bin2bn(sig, primelen, r);
    BN_bin2bn(sig + primelen, primelen, s);
    ECDSA_SIG_set0(ecsig, r, s);

    if (ECDSA_do_verify(digest, mdlen, ecsig, signkey) < 1) {
        goto fail;
    }
    ret = 1;

fail:
    if (mdctx != NULL) {
        EVP_MD_CTX_free(mdctx);
    }
    return ret;
}

EC_POINT *get_point_from_connector (unsigned char *connector, int len, const EC_GROUP *group, BN_CTX *bnctx)
{
    EC_POINT *P = NULL;
    BIGNUM *x = NULL, *y = NULL;
    unsigned char *unburl = NULL, *unbpt = NULL;
    char *dot1, *dot2, *sstr, *estr;
    int unburllen, ntok, unbptlen, ptlen;

    if ((unburl = (unsigned char *)malloc((len*4)/3)) == NULL) {
        goto fail;
    }
    if (((dot1 = strstr((char *)connector, ".")) == NULL) ||
        ((dot2 = strstr((char *)dot1+1, ".")) == NULL)) {
        goto fail;
    }
    dot1 = dot1+1;
    unburllen = base64urldecode(unburl, (unsigned char *)dot1, dot2 - dot1);
    if ((ntok = get_json_data((char *)unburl, unburllen, &sstr, &estr, 2, "netAccessKey", "crv")) != 1) {
        goto fail;
    }
    if (strncmp(sstr, "P-256", 5) == 0) {
        if (EC_GROUP_get_curve_name(group) != NID_X9_62_prime256v1) {
            goto fail;
        }
        ptlen = 32;
    } else if (strncmp(sstr, "P-384", 5) == 0) {
        if (EC_GROUP_get_curve_name(group) != NID_secp384r1) {
            goto fail;
        }
        ptlen = 48;
    } else if (strncmp(sstr, "P-521", 5) == 0) {
        if (EC_GROUP_get_curve_name(group) != NID_secp521r1) {
            goto fail;
        }
        ptlen = 66;
#ifdef HAS_BRAINPOOL
    } else if (strncmp(sstr, "BP-256", 6) == 0) {
        if (EC_GROUP_get_curve_name(group) != NID_brainpoolP256r1) {
            goto fail;
        }
        ptlen = 32;
    } else if (strncmp(sstr, "BP-384", 6) == 0) {
        if (EC_GROUP_get_curve_name(group) != NID_brainpoolP384r1) {
            goto fail;
        }
        ptlen = 48;
    } else if (strncmp(sstr, "BP-512", 6) == 0) {
        if (EC_GROUP_get_curve_name(group) != NID_brainpoolP512r1) {
            goto fail;
        }
        ptlen = 64;
#endif    
    } else {
        goto fail;
    }
    if ((unbpt = (unsigned char *)malloc(ptlen)) == NULL) {
        goto fail;
    }
    
    if (((P = EC_POINT_new(group)) == NULL) || ((x = BN_new()) == NULL) ||
        ((y = BN_new()) == NULL)) {
        goto fail;
    }

    if ((ntok = get_json_data((char *)unburl, unburllen, &sstr, &estr, 2, "netAccessKey", "x")) != 1) {
        goto fail;
    }
    memset(unbpt, 0xee, ptlen);
    unbptlen = base64urldecode(unbpt, (unsigned char *)sstr, (int)(estr - sstr));
    BN_bin2bn((unsigned char *)unbpt, unbptlen, x);

    if ((ntok = get_json_data((char *)unburl, unburllen, &sstr, &estr, 2, "netAccessKey", "y")) != 1) {
        goto fail;
    }
    memset(unbpt, 0xee, ptlen);
    unbptlen = base64urldecode(unbpt, (unsigned char *)sstr, (int)(estr - sstr));
    BN_bin2bn((unsigned char *)unbpt, unbptlen, y);

    if (!EC_POINT_set_affine_coordinates_GFp(group, P, x, y, bnctx)) {
        printf("can't set affine coordinates!\n");
        goto fail;
    }
    if (!EC_POINT_is_on_curve(group, P, bnctx)) {
        printf("point is not on the curve!\n");
        goto fail;
    }

    if (0) {
fail:
        if (P != NULL) {
            EC_POINT_free(P);
            P = NULL;
        }
    }
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
    if (unburl != NULL) {
        free(unburl);
    }
    
    return P;
}
