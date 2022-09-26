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
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <net/if.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/stack.h>
#include <openssl/asn1.h>
#include <openssl/safestack.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include "ieee802_11.h"
#include "aes_siv.h"
#include "service.h"
#include "talk2ca.h"
#include "tlv.h"
#include "hkdf.h"
#include "os_glue.h"
#include "utils.h"

/*
 * DPP debugging bitmask
 */
#define DPP_DEBUG_ERR           0x0001
#define DPP_DEBUG_PROTOCOL_MSG  0x0002
#define DPP_DEBUG_STATE_MACHINE 0x0004
#define DPP_DEBUG_CRYPTO        0x0008
#define DPP_DEBUG_CRYPTO_VERB   0x0010
#define DPP_DEBUG_TRACE         0x0020
#define DPP_DEBUG_PKI           0x0040
#define DPP_DEBUG_ANY           0xffff

/*
 * DPP status codes
 */
#define STATUS_OK                       0
#define STATUS_NOT_COMPATIBLE           1
#define STATUS_AUTH_FAILURE             2
#define STATUS_DECRYPT_FAILURE          3
#define STATUS_CONFIGURE_FAILURE        5
#define STATUS_RESPONSE_PENDING         6
#define STATUS_INVALID_CONNECTOR        7
#define STATUS_NO_MATCH                 8
#define STATUS_CONFIG_REJECTED          9
#define STATUS_NO_AP                    10
#define STATUS_CONFIGURE_PENDING        11
#define STATUS_CSR_NEEDED               12
#define STATUS_CSR_BAD                  13
#define STATUS_NEW_KEY_NEEDED           14

/*
 * DPP roles
 */
#define DPP_ENROLLEE            0x01
#define DPP_CONFIGURATOR        0x02

/*
 * some useful defines
 */
#define P256_COORD_LEN          32
#define P384_COORD_LEN          48
#define P512_COORD_LEN          64
#define P521_COORD_LEN          66

/*
 * a list of BSSIDs and frequencies to chirp on
 */
struct chirpdest {
    TAILQ_ENTRY(chirpdest) entry;
    char bssid[ETH_ALEN];
    unsigned long freq;
};
TAILQ_HEAD(fubar, chirpdest) chirpdests;

struct cpolicy {
    TAILQ_ENTRY(cpolicy) entry;
    char akm[10];        // "psk" or "sae" or "dpp"
    char auxdata[80];    // password or san
    char ssid[33];
};
TAILQ_HEAD(frobnitz, cpolicy) cpolicies;

struct candidate {
    TAILQ_ENTRY(candidate) entry;
    dpp_handle handle;
    unsigned char version;

    struct chirpdest *chirpto;
    EC_KEY *peer_bootstrap;
    /*
     * DPP auth stuff
     */
    EC_KEY *my_proto;
    EC_POINT *peer_proto;
    unsigned char dialog_token;
    timerid t0;                           
#define DPP_FAILED              0
#define DPP_NOTHING             5
#define DPP_BOOTSTRAPPED        6       /* the initiator's state */
#define DPP_AWAITING            7       /* the responder's state */    
#define DPP_AUTHENTICATING      8
#define DPP_AUTHENTICATED       9
#define DPP_PROVISIONING        10
#define DPP_CA_RESP_PENDING     11
#define DPP_PROVISIONED         12
    unsigned short state;
    BIGNUM *m;
    unsigned char core;                 /* configurator or enrollee for this time */
    int is_initiator;
    int mauth;                          /* mutual authentication (1) or not (0) */
    unsigned char k1[SHA512_DIGEST_LENGTH];
    unsigned char k2[SHA512_DIGEST_LENGTH];
    unsigned char bk[SHA512_DIGEST_LENGTH];
    unsigned char ke[SHA512_DIGEST_LENGTH];
    unsigned char peernonce[SHA512_DIGEST_LENGTH/2];
    unsigned char mynonce[SHA512_DIGEST_LENGTH/2];
    unsigned char buffer[8192];         /* can be fragmented during config exchange */
    int bufferlen;
    unsigned char retrans;
    int mtu;
    unsigned char *frame;
    int framelen;
    /*
     * dpp config stuff
     */
    EC_POINT *peernewproto;             /* if Configurator asks for a new protocol key */
    EC_KEY *mynewproto;
    int newprimelen;                    /* size of new group */
    int nextfragment;                   /* where in the buffer we're doing frag/reass */
    int nextid;                         /* next expected fragment id (used by enrollees) */
    char enrollee_name[80];
    char enrollee_role[10];
    char *p7;
    int p7len;
    char *csrattrs;
    int csrattrs_len;
    unsigned char field;
    unsigned char enonce[SHA512_DIGEST_LENGTH/2];
};

#define state_to_string(x) (x) == DPP_FAILED ? "DPP failed" : \
                           (x) == DPP_NOTHING ? "DPP nothing" : \
                           (x) == DPP_BOOTSTRAPPED ? "DPP bootstrapped":           \
                           (x) == DPP_AWAITING ? "DPP awaiting" : \
                           (x) == DPP_AUTHENTICATING ? "DPP authenticating" : \
                           (x) == DPP_AUTHENTICATED ? "DPP authenticated" : \
                           (x) == DPP_PROVISIONING ? "DPP provisioning" : \
                           (x) == DPP_CA_RESP_PENDING ? "DPP CA response pending" : \
                           (x) == DPP_PROVISIONED ? "DPP provisioned" : \
                           "unknown"

/*
 * stuff that gets provisioned when we are an enrollee
 */
static EC_KEY *netaccesskey;
static char *connector = NULL;
static int connector_len = 0;
static unsigned char discovery_transaction = 0;
static EC_KEY *configurator_signkey;   /* we're an enrollee, this isn't ours */
static unsigned char csign_kid[KID_LENGTH];

/*
 * our instance of DPP
 */
struct _dpp_instance {
    TAILQ_HEAD(blah, candidate) peers;
    EC_KEY *bootstrap;
    EC_KEY *signkey;            /* we're the configurator, this is ours */
    const EC_GROUP *group;
    const EVP_MD *hashfcn;
    char core;                  /* capabile of being configurator or enrollee */
    char newoc;                 /* switch to this new operating class after sending DDP Auth Req */
    char newchan;               /* swithc to this new channel after sending DPP Auth Req */
    char enrollee_role[10];     /* role for an enrollee */
    int enterprise;             /* whether configurator provisions enterprise credentials */
    char mudurl[80];            /* MUD URL for an enrollee */
    int group_num;              /* these are handy to keep around */
    int primelen;               /* and not have to continually */
    int digestlen;              /* compute them from "bootstrap" */
    unsigned short newgroup;    /* 0 if not needed, NID of curve otherwise */
    EC_KEY *Pc;                 /* configurator's new protocol key (reused) */
    int noncelen;
    int nid;                    /* ditto */
    char caip[40];
    char *cacert;
    int cacert_len;
} dpp_instance;

/*
 * a linked list of values extracted from an ASN.1 SET for a given attribute
 */
typedef struct setval_t {
    struct setval_t *next;
    enum {
        SETVAL_ERROR, SETVAL_NID, SETVAL_STR, SETVAL_INT,
        SETVAL_OCTSTR, SETVAL_BITSTR
    } type;
    union {
        int nid;
        unsigned char *str;
        int integer;
        unsigned char *octstr;
        unsigned char *bitstr;
    };
} setval;

/*
 * forward reference
 */
static void start_dpp_chirp (timerid id, void *data);
/*
 * global variables
 */
extern service_context srvctx;

static dpp_handle next_handle = 0;
static int dpp_initialized = 0;
static BN_CTX *bnctx = NULL;
static int debug = 0;
static int do_chirp;

static unsigned char wfa_dpp[4] = { 0x50, 0x6f, 0x9a, 0x1a };
static unsigned char dpp_proto_elem_req[3] = { 0x6c, 0x08, 0x00 };
static unsigned char dpp_proto_elem_resp[3] = { 0x6c, 0x08, 0x7f };
static unsigned char dpp_proto_id[7] = { 0xdd, 0x05, 0x50, 0x6f, 0x9a, 0x1a, 0x01 };
    
//----------------------------------------------------------------------
// debugging routines
//----------------------------------------------------------------------

static void
dump_buffer (unsigned char *buf, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        if (i && (i%4 == 0)) {
            printf(" ");
        }
        if (i && (i%32 == 0)) {
            printf("\n");
        }
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static void
print_buffer (char *str, unsigned char *buf, int len)
{
    printf("%s:\n", str);
    dump_buffer(buf, len);
    printf("\n");
}

static void
debug_buffer (int level, char *str, unsigned char *buf, int len)
{
    if (debug & level) {
        print_buffer(str, buf, len);
    }
}

static void
pp_a_bignum (char *str, BIGNUM *bn)
{
    unsigned char *buf;
    int len;

    len = BN_num_bytes(bn);
    if ((buf = malloc(len)) == NULL) {
        return;
    }
    BN_bn2bin(bn, buf);
    print_buffer(str, buf, len);
    free(buf);
}

static void
debug_a_bignum (int level, char *str, BIGNUM *bn)
{
    if (debug & level) {
        pp_a_bignum(str, bn);
    }
}

static void
print_ec_point (char *str, EC_POINT *point)
{
    BIGNUM *x = NULL, *y = NULL;
    
    if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
        !EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, point, x, y, bnctx)) {
        goto fin;
    }
    printf("%s\n", str);
    pp_a_bignum("x", x);
    pp_a_bignum("y", y);
fin:
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
}
static void
debug_ec_point (int level, char *str, EC_POINT *point)
{
    if (debug & level) {
        print_ec_point(str, point);
    }
}

static void
debug_ec_key (int level, char *str, EC_KEY *key)
{
    const EC_POINT *pub;

    if (debug & level) {
        if ((pub = EC_KEY_get0_public_key(key)) != NULL) {
            print_ec_point(str, (EC_POINT *)pub);
        }
    }
}

static void
debug_asn1_ec(int level, char *str, EC_KEY *key, int b64it)
{
    unsigned char *asn1, data[1024];
    int asn1len, i, num;
    BIO *bio = NULL, *bout = NULL;

    if (debug & level) {
        if ((bio = BIO_new(BIO_s_mem())) == NULL) {
            printf("%s: CAN'T CREATE A BIO TO PRINT ASN.1!\n", str);
            return;
        }
        if (b64it) {
            bout = BIO_new(BIO_s_file());
            BIO_set_fp(bout, stdout, BIO_NOCLOSE);
        }
    
        (void)i2d_EC_PUBKEY_bio(bio, key);
        (void)BIO_flush(bio);
        asn1len = BIO_get_mem_data(bio, &asn1);
        printf("%s:\n", str);
        if (b64it) {
            num = EVP_EncodeBlock(data, asn1, asn1len);
            BIO_write(bout, data, num);
            (void)BIO_flush(bout);
            BIO_free(bout);
        } else {
            for (i = 0; i < asn1len; i++) {
                printf("%02x", asn1[i]);
            }
            printf("\n");
        }
        printf("\n");
        BIO_free(bio);
    }
    return;
}

static void
dpp_debug (int level, const char *fmt, ...)
{
    va_list argptr;

    if (debug & level) {
        va_start(argptr, fmt);
        vfprintf(stdout, fmt, argptr);
        va_end(argptr);
    }
}

static void
dump_tlvs (unsigned char *attributes, int len)
{
    int i;
    TLV *tlv;

    tlv = (TLV *)attributes;
    TLV_foreach(tlv, i, len) {
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "type %s, length %d, ",
                  TLV_type_string(tlv), TLV_length(tlv));
        debug_buffer(DPP_DEBUG_PROTOCOL_MSG, "value", TLV_value(tlv), TLV_length(tlv));
    }
}

//----------------------------------------------------------------------
// routines common between initiator and responder
//----------------------------------------------------------------------

static int
prime_len_by_curve (int groupnum)
{
    int len = 0;

    switch (groupnum) {
        case 19:                /* NIST p256 */
        case 28:                /* brainpool p256 */
            len = 32;
            break;
        case 20:                /* NIST p384 */
        case 29:                /* brainpool p384 */
            len = 48;
            break;
        case 30:                /* brainpool p512 */
            len = 64;
            break;
        case 21:                /* NIST p521 */
            len = 66;
            break;
        case 25:                /* SEC p192 */
            len = 24;
            break;
        case 26:                /* SEC p224 */
            len = 28;
            break;
        default:
            break;
    }
    return len;
}

EC_KEY *generate_new_protocol_key (unsigned short group)
{
    EC_KEY *newkey = NULL;

    switch (group) {
        case 19:
            newkey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            break;
        case 20:
            newkey = EC_KEY_new_by_curve_name(NID_secp384r1);
            break;
        case 21:
            newkey = EC_KEY_new_by_curve_name(NID_secp521r1);
            break;
        case 25:
            newkey = EC_KEY_new_by_curve_name(NID_X9_62_prime192v1);
            break;
        case 26:
            newkey = EC_KEY_new_by_curve_name(NID_secp224r1);
            break;
#ifdef HAS_BRAINPOOL
        case 28:
            newkey = EC_KEY_new_by_curve_name(NID_brainpoolP256r1);
            break;
        case 29:
            newkey = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);
            break;
        case 30:
            newkey = EC_KEY_new_by_curve_name(NID_brainpoolP512r1);
            break;
#endif  /* HAS_BRAINPOOL */
        default:
            break;
    }
    if (newkey != NULL) {
        if (!EC_KEY_generate_key(newkey)) {
            dpp_debug(DPP_DEBUG_ERR, "cannot create new protocol key\n");
            EC_KEY_free(newkey);
            newkey = NULL;
        }
    }
    return newkey;
}

static void
setup_dpp_action_frame (struct candidate *peer, unsigned char frametype)
{
    dpp_action_frame *frame;

    frame = (dpp_action_frame *)peer->frame;
    memcpy(frame->oui_type, wfa_dpp, sizeof(wfa_dpp));
    frame->cipher_suite = 1;
    frame->frame_type = frametype;

    return;
}

static int
send_dpp_action_frame (struct candidate *peer)
{
    dpp_action_frame *frame;

    frame = (dpp_action_frame *)peer->frame;
    memcpy(frame->attributes, peer->buffer, peer->bufferlen);
    return transmit_auth_frame(peer->handle, peer->frame, peer->bufferlen + sizeof(dpp_action_frame));
}

/*
 * IEEE order is little endian, ensure things go out (hton) correctly 
 * and can be coverted (ntoh) after receipt
 */
static void
ieeeize_hton_attributes (unsigned char *attributes, int len)
{
    unsigned char *ptr = attributes;
    TLV *tlv;

    while (ptr < (attributes + len)) {
        tlv = (TLV *)ptr;
        ptr = (unsigned char *)TLV_next(tlv);
        tlv->type = ieee_order(tlv->type);
        tlv->length = ieee_order(tlv->length);
    }
}

static void ieeeize_ntoh_attributes (unsigned char *attributes, int len)
{
    unsigned char *ptr = attributes;
    TLV *tlv;

    while (ptr < (attributes + len)) {
        tlv = (TLV *)ptr;
        tlv->type = ieee_order(tlv->type);
        tlv->length = ieee_order(tlv->length);
        ptr = (unsigned char *)TLV_next(tlv);
    }
}

static int
compute_bootstrap_key_hash (EC_KEY *key, unsigned char *digest)
{
    int asn1len;
    BIO *bio;
    EVP_MD_CTX *mdctx;
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
    unsigned char *asn1;

    memset(digest, 0, SHA256_DIGEST_LENGTH);

    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
        return -1;
    }
    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        BIO_free(bio);
        return -1;
    }
    (void)i2d_EC_PUBKEY_bio(bio, key);
    (void)BIO_flush(bio);
    asn1len = BIO_get_mem_data(bio, &asn1);

    EVP_DigestInit(mdctx, EVP_sha256());
    EVP_DigestUpdate(mdctx, asn1, asn1len);
    EVP_DigestFinal(mdctx, digest, &mdlen);

    BIO_free(bio);
    EVP_MD_CTX_free(mdctx);
    return mdlen;
}

static void
next_dpp_chirp (timerid id, void *data)
{
    struct candidate *peer = (struct candidate *)data;

    if (peer->chirpto == NULL) {
        /*
         * we ran through the chirp list so wait 30s and do it all over again
         */
        dpp_debug(DPP_DEBUG_TRACE, "exhausted chirp list, wait a bit and try again\n");
        peer->t0 = srv_add_timeout(srvctx, SRV_SEC(30), start_dpp_chirp, peer);
        return;
    }
    /*
     * the chirp is already in the buffer, just change channels and send again
     */
    if (change_dpp_freq(peer->handle, peer->chirpto->freq) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "can't change channel to chirp!\n");
    }
    if (send_dpp_action_frame(peer)) {
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "chirp on %ld...\n", peer->chirpto->freq);
    }
    /*
     * next!
     */
    peer->chirpto = TAILQ_NEXT(peer->chirpto, entry);
    peer->t0 = srv_add_timeout(srvctx, SRV_SEC(5), next_dpp_chirp, peer);
    return;
}

static void
start_dpp_chirp (timerid id, void *data)
{
    struct candidate *peer = (struct candidate *)data;
    unsigned char bootkeyhash[SHA256_DIGEST_LENGTH], *asn1;
    TLV *tlv;
    int asn1len;
    BIO *bio;
    EVP_MD_CTX *mdctx;
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
    
    memset(peer->buffer, 0, sizeof(peer->buffer));
    memset(bootkeyhash, 0, SHA256_DIGEST_LENGTH);
    peer->bufferlen = 0;
    tlv = (TLV *)peer->buffer;

    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
        goto fin;
    }
    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        BIO_free(bio);
        goto fin;
    }
    (void)i2d_EC_PUBKEY_bio(bio, dpp_instance.bootstrap);
    (void)BIO_flush(bio);
    asn1len = BIO_get_mem_data(bio, &asn1);

    /*
     * the entirety of the chirp is a hash of "chirp" and our bootstrapping key
     */
    EVP_DigestInit(mdctx, EVP_sha256());
    EVP_DigestUpdate(mdctx, "chirp", strlen("chirp"));
    EVP_DigestUpdate(mdctx, asn1, asn1len);
    EVP_DigestFinal(mdctx, bootkeyhash, &mdlen);

    BIO_free(bio);
    EVP_MD_CTX_free(mdctx);

    tlv = TLV_set_tlv(tlv, RESPONDER_BOOT_HASH, SHA256_DIGEST_LENGTH, bootkeyhash);
    ieeeize_hton_attributes(peer->buffer, (int)((unsigned char *)tlv - peer->buffer));

    setup_dpp_action_frame(peer, DPP_CHIRP);
    peer->bufferlen = (int)((unsigned char *)tlv - peer->buffer);
    peer->chirpto = TAILQ_FIRST(&chirpdests);
    if (change_dpp_freq(peer->handle, peer->chirpto->freq) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "can't change channel to chirp!\n");
    }
    if (send_dpp_action_frame(peer)) {
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "chirp on %ld...\n", peer->chirpto->freq);
    }
fin:
    /*
     * keep chirping, when we get a response we'll stop
     */
    peer->chirpto = TAILQ_NEXT(peer->chirpto, entry);
    peer->t0 = srv_add_timeout(srvctx, SRV_SEC(5), next_dpp_chirp, peer);
    return;
}

static void
send_term_notice (timerid id, void *data)
{
    struct candidate *peer = (struct candidate *)data;
    
    term(0, peer->handle);
}

static void
destroy_peer (timerid id, void *data)
{
    struct candidate *peer = (struct candidate *)data;

    srv_rem_timeout(srvctx, peer->t0);
    if (peer->my_proto != NULL) {
        EC_KEY_free(peer->my_proto);
    }
    if (peer->mynewproto != NULL) {
        EC_KEY_free(peer->mynewproto);
    }
    if (peer->peernewproto != NULL) {
        EC_POINT_clear_free(peer->peernewproto);
    }
    EC_POINT_clear_free(peer->peer_proto);
    EC_KEY_free(peer->peer_bootstrap);
    BN_free(peer->m);
    free(peer->frame);
    if (connector != NULL) {
        free(connector);
    }
    /*
     * zero out our secrets and other goo
     */
    memset(peer->k1, 0, SHA512_DIGEST_LENGTH);
    memset(peer->k2, 0, SHA512_DIGEST_LENGTH);
    memset(peer->ke, 0, SHA512_DIGEST_LENGTH);
    memset(peer->peernonce, 0, SHA512_DIGEST_LENGTH/2);
    memset(peer->mynonce, 0, SHA512_DIGEST_LENGTH/2);
    memset(peer->buffer, 0, 8192);
    TAILQ_REMOVE(&dpp_instance.peers, peer, entry);
    free(peer);
    return;
}

static void
fail_dpp_peer (struct candidate *peer)
{
    /*
     * mark the peer failed but let the rest of the processing
     * finish (e.g. send a frame indicating failure) and do the
     * actual cleanup off a timer that should fire "immediately."
     */
    if (peer->state == DPP_FAILED) {
        /* 
         * don't let 2 timers get set to free the peer
         */
        return;
    }
    peer->state = DPP_FAILED;
    /*
     * if we're chirping then restart everything, set the timer for 5s to allow
     * this failure to completely process (for any 2nd timers potentially coming
     * in here, we want to stay with state = DPP_FAILED) then start all over again
     */
    if (do_chirp) {
        peer->t0 = srv_add_timeout(srvctx, SRV_SEC(5), start_dpp_chirp, peer);
    } else {
        (void)srv_add_timeout(srvctx, SRV_MSEC(1), destroy_peer, peer);
    }
}

static void
retransmit_config (timerid id, void *data)
{
    struct candidate *peer = (struct candidate *)data;
    
    /*
     * if the peer doesn't exists anymore or if the peer is in FAILED 
     * state then just return. Shouldn't happen but those are famous
     * last words. 
     */
    if (peer == NULL) {
        return;
    }
    if (peer->state == DPP_FAILED) {
        return;
    }
    if (peer->retrans > 5) {
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "too many retransmits, bailing!\n");
        fail_dpp_peer(peer);
    } else {
        peer->retrans++;
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "retransmitting %d byte frame config frame...for the %d time\n",
                  peer->framelen, peer->retrans);
        if (transmit_config_frame(peer->handle, peer->field, peer->frame, peer->framelen)) {
            peer->t0 = srv_add_timeout(srvctx, SRV_SEC(5), retransmit_config, peer);
        }
    }
    return;
}

//----------------------------------------------------------------------
// DPP config exchange routines
//----------------------------------------------------------------------

static int
send_dpp_config_frame (struct candidate *peer, unsigned char field)
{
    int ret;
    gas_action_req_frame *gareq;
    gas_action_resp_frame *garesp;
    gas_action_comeback_resp_frame *gacresp;
    gas_action_comeback_req_frame *gacreq;
    
    dpp_debug(DPP_DEBUG_TRACE, "sending a %s dpp config frame\n", 
              field == GAS_INITIAL_REQUEST ? "GAS_INITIAL_REQUEST" : \
              field == GAS_INITIAL_RESPONSE ? "GAS_INITIAL_RESPONSE" : \
              field == GAS_COMEBACK_REQUEST ? "GAS_COMEBACK_REQUEST" : \
              field == GAS_COMEBACK_RESPONSE ? "GAS_COMEBACK_RESPONSE" : "unknown");
    switch (field) {
        case GAS_INITIAL_REQUEST:
            /*
             * fill in the generic header goo
             */
            gareq = (gas_action_req_frame *)peer->frame;
            gareq->dialog_token = peer->dialog_token;
            memcpy(gareq->ad_proto_elem, dpp_proto_elem_req, sizeof(dpp_proto_elem_req));
            memcpy(gareq->ad_proto_id, dpp_proto_id, sizeof(dpp_proto_id));
            /*
             * fill in the response
             */
            gareq->query_reqlen = peer->bufferlen;
            memcpy(gareq->query_req, peer->buffer, peer->bufferlen);
            peer->field = field;
            peer->framelen = peer->bufferlen + sizeof(gas_action_req_frame);
            break;
        case GAS_INITIAL_RESPONSE:
            if ((peer->bufferlen > peer->mtu) || (peer->state == DPP_CA_RESP_PENDING)) {
                /*
                 * fill in the generic header goo
                 */
                garesp = (gas_action_resp_frame *)peer->frame;
                garesp->dialog_token = peer->dialog_token;
                peer->nextfragment = 0;         // where we start fragmenting... the beginning!
                memcpy(garesp->ad_proto_elem, dpp_proto_elem_resp, sizeof(dpp_proto_elem_resp));
                memcpy(garesp->ad_proto_id, dpp_proto_id, sizeof(dpp_proto_id));
                /*
                 * comeback delay of 1 indicates fragmentation and we send back a 0 length response
                 * comeback delay of 1000 indicates a real "come back later"
                 */
                garesp->status_code = 0;       // success!
                if (peer->state == DPP_CA_RESP_PENDING) {
                    garesp->comeback_delay = 1000;
                    dpp_debug(DPP_DEBUG_TRACE, "\t(still waiting for PKCS7, comeback in 1000 TUs)\n");
                } else {
                    garesp->comeback_delay = 1;
                    dpp_debug(DPP_DEBUG_TRACE, "\t(sending 1st fragment)\n");
                }
                garesp->query_resplen = 0;
                peer->field = field;
                peer->framelen = sizeof(gas_action_resp_frame);
            } else {
                /*
                 * fill in the generic header goo
                 */
                garesp = (gas_action_resp_frame *)peer->frame;
                garesp->dialog_token = peer->dialog_token;
                garesp->status_code = 0; // success! 
                garesp->comeback_delay = 0;
                dpp_debug(DPP_DEBUG_TRACE, "\t(sending whole message)\n");
                memcpy(garesp->ad_proto_elem, dpp_proto_elem_resp, sizeof(dpp_proto_elem_resp));
                memcpy(garesp->ad_proto_id, dpp_proto_id, sizeof(dpp_proto_id));

                garesp->query_resplen = peer->bufferlen;
                memcpy(garesp->query_resp, peer->buffer, peer->bufferlen);
                peer->field = field;
                peer->framelen = peer->bufferlen + sizeof(gas_action_resp_frame);
            }
            break;
        case GAS_COMEBACK_RESPONSE:
            gacresp = (gas_action_comeback_resp_frame *)peer->frame;
            gacresp->dialog_token = peer->dialog_token;
            memcpy(gacresp->ad_proto_elem, dpp_proto_elem_resp, sizeof(dpp_proto_elem_resp));
            memcpy(gacresp->ad_proto_id, dpp_proto_id, sizeof(dpp_proto_id));
            gacresp->status_code = 0;           // success!
            if (peer->state == DPP_CA_RESP_PENDING) {
                /*
                 * just keep telling the peer to wait
                 */
                dpp_debug(DPP_DEBUG_TRACE, "\t(still don't have PKCS7, come back in 1000 TUs)\n");
                gacresp->comeback_delay = 1000;
                gacresp->fragment_id = 0;
                gacresp->query_resplen = 0;
            } else {
                /*
                 * we're just fragmenting our response...
                 *
                 * fill in the fragment number (+1 because it starts at 1 and nextfrag starts at 0)
                 * record how big the next chunk will be
                 */
                gacresp->comeback_delay = 0;
                gacresp->fragment_id = peer->nextfragment/(peer->mtu - sizeof(gas_action_comeback_resp_frame));
                if ((peer->bufferlen - peer->nextfragment) > (peer->mtu - sizeof(gas_action_comeback_resp_frame))) {
                    gacresp->query_resplen = peer->mtu - sizeof(gas_action_comeback_resp_frame);
                    gacresp->fragment_id |= 0x80;   // more fragments!
                    dpp_debug(DPP_DEBUG_TRACE, "\t(next fragment of %d (%d), there are more...\n",
                              gacresp->query_resplen, gacresp->fragment_id);
                } else {
                    gacresp->query_resplen = peer->bufferlen - peer->nextfragment;
                    dpp_debug(DPP_DEBUG_TRACE, "\t(final fragment of %d (%d)...\n",
                              gacresp->query_resplen, gacresp->fragment_id);
		    print_buffer("First 32 octets of message", peer->buffer+peer->nextfragment, 32);
                }
                memcpy(gacresp->query_resp, peer->buffer + peer->nextfragment, gacresp->query_resplen);
                peer->nextfragment += gacresp->query_resplen;
                peer->field = field;
            }
            peer->framelen = gacresp->query_resplen + sizeof(gas_action_comeback_resp_frame);
            break;
        case GAS_COMEBACK_REQUEST:
            gacreq = (gas_action_comeback_req_frame *)peer->frame;
            gacreq->dialog_token = peer->dialog_token;
            peer->field = field;
            peer->framelen = sizeof(gas_action_comeback_req_frame);
            break;
        default:
            return  -1;
    }
    ret = transmit_config_frame(peer->handle, field, peer->frame, peer->framelen);
    return ret;
}

static void
retransmit_auth (timerid id, void *data)
{
    struct candidate *peer = (struct candidate *)data;
    dpp_action_frame *frame;
    
    /*
     * if the peer doesn't exists anymore or if the peer is in FAILED 
     * state then just return. Shouldn't happen but those are famous
     * last words. 
     */
    if (peer == NULL) {
        return;
    }
    if (peer->state == DPP_FAILED) {
        return;
    }
    if (peer->retrans > 5) {
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "too many retransmits, bailing!\n");
        fail_dpp_peer(peer);
    }
    frame = (dpp_action_frame *)peer->frame;
    memcpy(frame->attributes, peer->buffer, peer->bufferlen);
    if (transmit_auth_frame(peer->handle, peer->frame, peer->bufferlen + sizeof(dpp_action_frame))) {
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "retransmitting...for the %d time\n", peer->retrans);
        peer->t0 = srv_add_timeout(srvctx, SRV_SEC(2), retransmit_auth, peer);
        peer->retrans++;
    }
    return;
}

//----------------------------------------------------------------------
// DPP discovery exchange routines
//----------------------------------------------------------------------

static int
send_dpp_discovery_frame (unsigned char frametype, unsigned char status, 
                          unsigned char tid, unsigned char transaction_id)
{
    TLV *tlv;
    dpp_action_frame *frame;
    unsigned char framebuf[1024];  // not gonna fragment a discovery frame
    unsigned char buffer[4096];
    int bufferlen;

    memset(buffer, 0, sizeof(buffer));

    tlv = (TLV *)buffer;
    tlv = TLV_set_tlv(tlv, TRANSACTION_IDENTIFIER, 1, &tid);
    if (frametype == DPP_SUB_PEER_DISCOVER_RESP) {
        tlv = TLV_set_tlv(tlv, DPP_STATUS, 1, &status);
    }
    if (status == STATUS_OK) {
        tlv = TLV_set_tlv(tlv, CONNECTOR, connector_len, (unsigned char *)connector);
    }
    bufferlen = (int)((unsigned char *)tlv - buffer);

    ieeeize_hton_attributes(buffer, bufferlen);

    frame = (dpp_action_frame *)framebuf;
    memcpy(frame->oui_type, wfa_dpp, sizeof(wfa_dpp));
    frame->cipher_suite = 1;
    frame->frame_type = frametype;
    memcpy(frame->attributes, buffer, bufferlen);
    /*
     * TODO: retransmission....
     */
    return transmit_discovery_frame(transaction_id, framebuf, bufferlen + sizeof(dpp_action_frame));
}

int
dpp_begin_discovery (unsigned char transaction_id)
{
    dpp_debug(DPP_DEBUG_TRACE, "initiate DPP discovery...\n");

    if ((connector == NULL) || (connector_len < 1)) {
        dpp_debug(DPP_DEBUG_ERR, "don't have a connector for peer with tid %d\n", transaction_id);
        return -1;
    }

    send_dpp_discovery_frame (DPP_SUB_PEER_DISCOVER_REQ, STATUS_OK, transaction_id, transaction_id);
    
    return 1;
}

static int
process_dpp_discovery_connector (unsigned char *conn, int conn_len, unsigned char *pmk, unsigned char *pmkid)
{
    unsigned char unburl[1024], *dot, *nx = NULL;
    char *sstr, *estr;
    unsigned int mdlen = SHA512_DIGEST_LENGTH;
    int unburllen, ntok, ret = -1;
    EC_POINT *PK = NULL, *N = NULL;
    BIGNUM *x = NULL, *nkx = NULL, *pkx = NULL;
    EVP_MD_CTX *mdctx = NULL;
    const BIGNUM *nk;
    const EC_POINT *NK;
        
    memset(unburl, 0, sizeof(unburl));
    /*
     * base64url decode the JWS Protected Header then extract and decode the 'kid'
     */
    dot = (unsigned char *)strstr((char *)conn, ".");
    if ((unburllen = base64urldecode(unburl, conn, dot - conn)) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "Unable to base64url decode protected header of connector!\n");
        return -1;
    }
    if ((ntok = get_json_data((char *)unburl, unburllen, &sstr, &estr, 1, "kid")) != 1) {
        dpp_debug(DPP_DEBUG_ERR, "Failed to get 'kid' from connector's protected header!\n");
        return -1;
    }
    /*
     * if the 'kid' of the signer of the connector matches our configurator's 'kid'...
     */
    if (((int)(estr - sstr) != KID_LENGTH) || memcmp(csign_kid, sstr, KID_LENGTH)) {
        dpp_debug(DPP_DEBUG_ERR, "'kid' in peer's connector unknown!\n");
        debug_buffer(DPP_DEBUG_ERR, "configurator's 'kid'",
                     (unsigned char *)csign_kid, KID_LENGTH);
        debug_buffer(DPP_DEBUG_ERR, "'kid' in peer's connector",
                     (unsigned char *)sstr, (int)(estr - sstr));
        return -1;
    }
    dpp_debug(DPP_DEBUG_TRACE, "connector is signed by recognized configurator\n");
    
    /*
     * ...then validate the connector
     */
    if (validate_connector(conn, conn_len,
                           configurator_signkey, bnctx) < 0) {
        dpp_debug(DPP_DEBUG_ERR, "connector in DPP discovery frame is not valid!\n");
        return -1;
    }
    dpp_debug(DPP_DEBUG_TRACE, "connector in DPP Discovery frame is valid!\n");

    /*
     * extract the point from the valid connector, making sure it's same group as ours
     */
    if ((PK = get_point_from_connector(conn, conn_len, dpp_instance.group, bnctx)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "can't extract point from connector!\n");
        goto fail;;
    }
    if (((nk = EC_KEY_get0_private_key(netaccesskey)) == NULL) ||
        ((NK = EC_KEY_get0_public_key(netaccesskey)) == NULL)) {
        dpp_debug(DPP_DEBUG_ERR, "can't get my own network key! FAIL!\n");
        goto fail;
    }
    if (((N = EC_POINT_new(dpp_instance.group)) == NULL) || ((x = BN_new()) == NULL)) {
        dpp_debug(DPP_DEBUG_ERR, "can't create shared secret N!\n");
        goto fail;
    }
    if (!EC_POINT_mul(dpp_instance.group, N, NULL, PK, nk, bnctx) ||
        !EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, N, x, NULL, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "can't generate shared secret N.x!\n");
        goto fail;
    }
    if ((nx = (unsigned char *)malloc(dpp_instance.primelen)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "can't malloc shared secret nx!\n");
        goto fail;
    }
    /*
     * get hex of x-coordinate of shared secret
     */
    memset(nx, 0, dpp_instance.primelen);
    BN_bn2bin(x, nx + (dpp_instance.primelen - BN_num_bytes(x)));
    memset((char *)pmk, 0, SHA512_DIGEST_LENGTH);
    /*
     * ...derive PMK
     */
    hkdf(dpp_instance.hashfcn, 0, nx, dpp_instance.primelen, NULL, 0,
         (unsigned char *)"DPP PMK", strlen("DPP PMK"), pmk, dpp_instance.digestlen);
    print_buffer("pmk", pmk, dpp_instance.digestlen);
    /*
     * PMKID is based on x-coordinates of both public keys
     */
    if (((pkx = BN_new()) == NULL) || ((nkx = BN_new()) == NULL)) {
        dpp_debug(DPP_DEBUG_ERR, "can't allocate coordinates to generate PMKID!\n");
        goto fail;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, PK, pkx, NULL, bnctx) ||
        !EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, NK, nkx, NULL, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "can't get coordinates to generate PMKID!\n");
        goto fail;
    }
    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "can't generate PMKID!\n");
        goto fail;
    }
    memset(nx, 0, dpp_instance.primelen);
    EVP_DigestInit(mdctx, dpp_instance.hashfcn);
    if (BN_cmp(pkx, nkx) < 0) {
        BN_bn2bin(pkx, nx + (dpp_instance.primelen - BN_num_bytes(pkx)));
        EVP_DigestUpdate(mdctx, nx, dpp_instance.primelen);
        memset(nx, 0, dpp_instance.primelen);
        BN_bn2bin(nkx, nx + (dpp_instance.primelen - BN_num_bytes(nkx)));
        EVP_DigestUpdate(mdctx, nx, dpp_instance.primelen);
    } else {
        BN_bn2bin(nkx, nx + (dpp_instance.primelen - BN_num_bytes(nkx)));
        EVP_DigestUpdate(mdctx, nx, dpp_instance.primelen);
        memset(nx, 0, dpp_instance.primelen);
        BN_bn2bin(pkx, nx + (dpp_instance.primelen - BN_num_bytes(pkx)));
        EVP_DigestUpdate(mdctx, nx, dpp_instance.primelen);
    }
    EVP_DigestFinal(mdctx, pmkid, &mdlen);
    print_buffer("pmkid", pmkid, PMKID_LEN);   /* PMKID is fixed at 128 bits */

    ret = 1;
fail:
    if (mdctx != NULL) {
        EVP_MD_CTX_free(mdctx);
    }
    if (PK != NULL) {
        EC_POINT_free(PK);
    }
    if (N != NULL) {
        EC_POINT_free(N);
    }
    if (x != NULL) {
        BN_free(x);
    }
    if (pkx != NULL) {
        BN_free(pkx);
    }
    if (nkx != NULL) {
        BN_free(nkx);
    }
    if (nx != NULL) {
        free(nx);
    }
    return ret;
}

unsigned char
get_dpp_discovery_tid (void)
{
    return ++discovery_transaction;
}

int
process_dpp_discovery_frame (unsigned char *data, int len, unsigned char transaction_id,
                             unsigned char *pmk, unsigned char *pmkid)
{
    TLV *tlv;
    unsigned char tid, *val;
    dpp_action_frame *frame = (dpp_action_frame *)data;

    dpp_debug(DPP_DEBUG_TRACE, "got a DPP discovery frame!\n");
    if ((connector == NULL) || (connector_len < 1)) {
        dpp_debug(DPP_DEBUG_ERR, "don't have a connector to do discovery with!\n");
        return -1;
    }
    if (configurator_signkey == NULL) {
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "No configurator signing key, discarding DPP Discovery Request!\n");
        return 1;
    }

    ieeeize_ntoh_attributes(frame->attributes, len - sizeof(dpp_action_frame));

    tlv = (TLV *)frame->attributes;
    if (TLV_type(tlv) != TRANSACTION_IDENTIFIER) {
        dpp_debug(DPP_DEBUG_ERR, "1st TLV in dpp discovery request was not a transaction ID!\n");
        return -1;
    }
    memcpy(&tid, TLV_value(tlv), 1);
    tlv = TLV_next(tlv);
    switch (frame->frame_type) {
        case DPP_SUB_PEER_DISCOVER_REQ:
            if (TLV_type(tlv) != CONNECTOR) {
                dpp_debug(DPP_DEBUG_ERR, "2nd TLV in dpp discovery request was not a connector!\n");
                return -1;
            }
            if (process_dpp_discovery_connector(TLV_value(tlv), TLV_length(tlv), pmk, pmkid) < 1) {
                dpp_debug(DPP_DEBUG_ERR, "failed to process dpp discovery request!\n");
                send_dpp_discovery_frame(DPP_SUB_PEER_DISCOVER_RESP, STATUS_INVALID_CONNECTOR, tid, transaction_id);
                return -1;
            }
            /*
             * the tid is the peer's for it to identify our response
             * transaction_id is ours to identify the state of the exchange 
             */
            send_dpp_discovery_frame(DPP_SUB_PEER_DISCOVER_RESP, STATUS_OK, tid, transaction_id);
            break;
        case DPP_SUB_PEER_DISCOVER_RESP:
            /*
             * non-AP STAs should not have more than one active transaction at a time
             */
            if (tid != transaction_id) {
                dpp_debug(DPP_DEBUG_ERR, "got a spurious DPP Discovery Response (%d, expected %d)\n",
                          tid, discovery_transaction);
                return -1;
            }
            if (TLV_type(tlv) != DPP_STATUS) {
                dpp_debug(DPP_DEBUG_ERR, "2nd TLV in dpp discovery response was not status!\n");
                return -1;
            }
            val = TLV_value(tlv);
            if (*val != STATUS_OK) {
                dpp_debug(DPP_DEBUG_ERR, "Peer indicated error %d in discovery response status!\n", 
                          TLV_value(tlv));
                return -1;
            }
            tlv = TLV_next(tlv);
            if (TLV_type(tlv) != CONNECTOR) {
                dpp_debug(DPP_DEBUG_ERR, "3rd TLV in dpp discovery response was not a connector!\n");
                return -1;
            }
            if (process_dpp_discovery_connector(TLV_value(tlv), TLV_length(tlv), pmk, pmkid) < 1) {
                dpp_debug(DPP_DEBUG_ERR, "failed to process dpp discovery request!\n");
                return -1;
            }
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "unknown DPP Discovery frame %d\n", frame->frame_type);
            return -1;
    }
    return 1;
}

//----------------------------------------------------------------------
// cert and enterprise credential routines
//----------------------------------------------------------------------

/*
 * certificate_verify_callback()
 *      - explain the status of an X509 verification, we don't overrule the
 *        result, just report what happened.
 */
static int
certificate_verify_callback (int pre_verify_ok, X509_STORE_CTX *sctx)
{
    X509 *x509;
    char buf[80];
    
    if (!pre_verify_ok) {
        if ((x509 = X509_STORE_CTX_get_current_cert(sctx)) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "certificate store verify error %s\n",
                      X509_verify_cert_error_string(X509_STORE_CTX_get_error(sctx)));
        } else {
            dpp_debug(DPP_DEBUG_ERR, "error '%s' with certificate issued to ", 
                      X509_verify_cert_error_string(X509_STORE_CTX_get_error(sctx)));
            X509_NAME_oneline(X509_get_subject_name(x509), buf, sizeof(buf));
            dpp_debug(DPP_DEBUG_ERR, "%s, issued by ", buf);
            X509_NAME_oneline(X509_get_issuer_name(x509), buf, sizeof(buf));
            dpp_debug(DPP_DEBUG_ERR, "%s\n", buf);
        }
    } else {
        if ((x509 = X509_STORE_CTX_get_current_cert(sctx)) != NULL) {
            dpp_debug(DPP_DEBUG_PKI, "successful validation ('%s') of certificate issued to ", 
                      X509_verify_cert_error_string(X509_STORE_CTX_get_error(sctx)));
            X509_NAME_oneline(X509_get_subject_name(x509), buf, sizeof(buf));
            dpp_debug(DPP_DEBUG_PKI, "%s, issued by ", buf);
            X509_NAME_oneline(X509_get_issuer_name(x509), buf, sizeof(buf));
            dpp_debug(DPP_DEBUG_PKI, "%s\n", buf);
        }
    }
    return pre_verify_ok;
}

/*
 * extract X509 certificates out of a PKCS7 bag o'certs
 */
void
extract_certs (char *bag, int len, char *cacert, int cacert_len)
{
    PKCS7 *p7 = NULL, *cap7 = NULL;
    X509_STORE *store = NULL;
    X509 *x509 = NULL;
    STACK_OF(X509) *certs = NULL, *cacerts = NULL;
    EVP_ENCODE_CTX *ectx = NULL;
    X509_STORE_CTX *sctx = NULL;
    BIO *bio = NULL;
    unsigned char *asn1 = NULL;
    char fname[20];
    int i, asn1len, nid;

    if (bag == NULL || len < 1) {
        return;
    }
    if ((ectx = EVP_ENCODE_CTX_new()) == NULL) {
        return;
    }
    /*
     * if we got a CA cert then decode that
     */
    if ((cacert != NULL) && (cacert_len > 0)) {
        if ((asn1 = (unsigned char *)malloc(cacert_len)) == NULL) {
            goto fin;
        }
        i = cacert_len;
        EVP_DecodeInit(ectx);
        (void)EVP_DecodeUpdate(ectx, asn1, &i, (unsigned char *)cacert, cacert_len);
        asn1len = i;
        (void)EVP_DecodeFinal(ectx, &(asn1[i]), &i);
        asn1len += i;

        if ((bio = BIO_new_mem_buf(asn1, asn1len)) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "cannot create bio to get X509 from CA cert blob\n");
            goto fin;
        }
        if ((cap7 = d2i_PKCS7_bio(bio, NULL)) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "cannot extract X509 from CA cert blob\n");
            goto fin;
        }
        BIO_free(bio); bio = NULL;
        free(asn1); asn1 = NULL;
        
        nid = OBJ_obj2nid(cap7->type);
        switch (nid) {
            case NID_pkcs7_signed:
                cacerts = cap7->d.sign->cert;
                break;
            case NID_pkcs7_signedAndEnveloped:
                cacerts = cap7->d.signed_and_enveloped->cert;
                break;
            default:
                dpp_debug(DPP_DEBUG_ERR, "don't know how to handle this type (%d) of p7!\n", nid);
                goto fin;
        }
        dpp_debug(DPP_DEBUG_PKI, "got a CA certs p7 with %d certs in it\n", sk_X509_num(cacerts));
    }
    /*
     * decode the p7 with our cert in it...
     */
    if ((asn1 = (unsigned char *)malloc(len)) == NULL) {
        goto fin;
    }
    i = len;
    EVP_DecodeInit(ectx);
    (void)EVP_DecodeUpdate(ectx, asn1, &i, (unsigned char *)bag, len);
    asn1len = i;
    (void)EVP_DecodeFinal(ectx, &(asn1[i]), &i);
    asn1len += i;

    if ((bio = BIO_new_mem_buf(asn1, asn1len)) == NULL) {
        goto fin;
    }
    if ((p7 = d2i_PKCS7_bio(bio, NULL)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "cannot extract PKCS7 from p7 blob!\n");
        goto fin;
    }
    BIO_free(bio); bio = NULL;

    /*
     * the location of the certs depends on the type of PKCS7
     */
    nid = OBJ_obj2nid(p7->type);
    switch (nid) {
        case NID_pkcs7_signed:
            certs = p7->d.sign->cert;
            break;
        case NID_pkcs7_signedAndEnveloped:
            certs = p7->d.signed_and_enveloped->cert;
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "don't know how to handle this type (%d) of p7!\n", nid);
            goto fin;
    }
    dpp_debug(DPP_DEBUG_PKI, "got a p7 with %d certs in it\n", sk_X509_num(certs));
    
    if ((certs != NULL) &&
        ((store = X509_STORE_new()) != NULL) &&
        ((sctx = X509_STORE_CTX_new()) != NULL)) {

        /*
         * insert ourselves into the verification check chain
         */
        X509_STORE_set_verify_cb(store, certificate_verify_callback);
        /*
         * go through all the certs and find a self-signed one, make it the root
         * and stick ourselves into the process to get a notice of verification errors
         */
        for (i = 0; i < sk_X509_num(certs); i++) {
            if (X509_check_issued(sk_X509_value(certs, i),
                                  sk_X509_value(certs, i)) == X509_V_OK) {
                X509_STORE_add_cert(store, sk_X509_value(certs,i));
                break;
            }
        }
        if (i == sk_X509_num(certs)) {
            dpp_debug(DPP_DEBUG_PKI, "no self-signed cert in PKCS7 bag o'certs\n");
        }
        /*
         * be as generous as possible in interpreting what we got...
         * add self-signed certs from the CA p7 into the store as well in
         * case that's the trust root needed to validate our received cert
         */
        if (cacerts != NULL) {
            dpp_debug(DPP_DEBUG_PKI, "adding certs from CA p7 to store...\n");
            for (i = 0; i < sk_X509_num(cacerts); i++) {
                if (X509_check_issued(sk_X509_value(cacerts, i),
                                      sk_X509_value(cacerts, i)) == X509_V_OK) {
                    X509_STORE_add_cert(store, sk_X509_value(cacerts,i));
                    snprintf(fname, sizeof(fname), "cacert%d.pem", i);
                    if ((bio = BIO_new_file(fname, "w+")) == NULL) {
                        dpp_debug(DPP_DEBUG_ERR, "unable to save CA certificate to %s\n", fname);
                    } else {
                        PEM_write_bio_X509(bio, sk_X509_value(cacerts,i));
                    }
                    BIO_free(bio); bio = NULL;
                }
            }
        }
        for (i = 0; i < sk_X509_num(certs); i++) {
            /*
             * go through each certificate in the chain....
             */
            dpp_debug(DPP_DEBUG_TRACE, "checking certificate %d\n", i);
            if (!X509_STORE_CTX_init(sctx, store, NULL, certs)) {
                dpp_debug(DPP_DEBUG_ERR, "can't initialize STORE_CTX!\n");
                break;
            }
            x509 = sk_X509_value(certs, i);

//            X509_NAME_oneline(X509_get_subject_name(x509), buf, sizeof(buf));
//            dpp_debug(DPP_DEBUG_TRACE, "cert %d is for %s, ", i, buf);
//            X509_NAME_oneline(X509_get_issuer_name(x509), buf, sizeof(buf));
//            dpp_debug(DPP_DEBUG_TRACE, "issued by %s\n", buf);

            X509_STORE_CTX_set_cert(sctx, x509);
            /*
             * if the cert verifies then save it
             */
            if (X509_verify_cert(sctx) > 0) {
                dpp_debug(DPP_DEBUG_PKI, "certificate %d verified!\n", i);
            } else {
                dpp_debug(DPP_DEBUG_PKI, "certificate %d did not verify\n", i);
            }
            snprintf(fname, sizeof(fname), "mycert%d.pem", i);
            if ((bio = BIO_new_file(fname, "w+")) == NULL) {
                dpp_debug(DPP_DEBUG_ERR, "unable to save certificate to %s\n", fname);
                break;
            }
            PEM_write_bio_X509(bio, x509);
            BIO_free(bio); bio = NULL;
            X509_free(x509);
        }
    }
fin:
    if (p7 != NULL) {
        PKCS7_free(p7);
    }
    if (cap7 != NULL) {
        PKCS7_free(cap7);
    }
    if (asn1 != NULL) {
        free(asn1);
    }
    if (store != NULL) {
        X509_STORE_free(store);
    }
    if (sctx != NULL) {
        X509_STORE_CTX_free(sctx);
    }
    if (bio != NULL) {
        BIO_free(bio);
    }
    if (ectx != NULL) {
        EVP_ENCODE_CTX_free(ectx);
    }
}

/*
 * send out a base64-encoded DER encoded CSR Attributes SEQUENCE
 */
static int
gen_csrattrs (char *resp)
{
    ASN1_TYPE *asn1 = NULL; 
    CONF *cnf = NULL;
    long err;
    ASN1_OBJECT *o = NULL;
    STACK_OF(ASN1_OBJECT) *sk = NULL;
    BIO *bio = NULL, *b64 = NULL;
    unsigned char *buf = NULL, *data;
    char *str; 
    unsigned char *p;
    int i, objlen, totlen = 0, num = -1;
    
    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
        goto fail;
    }
    if ((b64 = BIO_new((BIO_METHOD *)BIO_f_base64())) == NULL) {
        goto fail;
    }
    bio = BIO_push(b64, bio);

    cnf = NCONF_new(NULL);
    if ((NCONF_load(cnf, "csrattrs.nconf", &err) != 0) &&
        ((str = NCONF_get_string(cnf, "default", "asn1")) != NULL) &&
        ((asn1 = ASN1_generate_nconf(str, cnf)) != NULL)) {
        totlen = i2d_ASN1_TYPE(asn1, NULL);
        i2d_ASN1_TYPE(asn1, (unsigned char **)&buf);
    } else {
        dpp_debug(DPP_DEBUG_TRACE, "failed to read csrattrs.nconf!\n");
        /*
         * if there's no csrattrs.conf or it parse wrongs just throw in the default
         */
        if ((sk = sk_ASN1_OBJECT_new_null()) == NULL) {
            goto fail;
        }
        o = (ASN1_OBJECT *)OBJ_nid2obj(NID_pkcs9_challengePassword);
        sk_ASN1_OBJECT_push(sk, o);
        o = (ASN1_OBJECT *)OBJ_nid2obj(dpp_instance.nid);
        sk_ASN1_OBJECT_push(sk, o);
        objlen = 0;
        for (i = sk_ASN1_OBJECT_num(sk)-1; i >= 0; i--) {
            objlen += i2d_ASN1_OBJECT(sk_ASN1_OBJECT_value(sk, i), NULL);
        }
        totlen = ASN1_object_size(1, objlen, V_ASN1_SEQUENCE);
        if ((buf = malloc(totlen + 1)) == NULL) {
            goto fail;
        }
        memset(buf, 0, totlen+1);
        p = (unsigned char *)buf;
        ASN1_put_object(&p, 1, objlen, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
        for (i = 0; i < sk_ASN1_OBJECT_num(sk); i++) {
            i2d_ASN1_OBJECT(sk_ASN1_OBJECT_value(sk, i), &p);
        }
    }

    BIO_write(bio, buf, totlen);
    (void)BIO_flush(bio);
    num = BIO_get_mem_data(bio, &data);
    memcpy(resp, data, num);
    resp[num] = '\0';
    dpp_debug(DPP_DEBUG_TRACE, "adding %d byte CSR %s\n", num, resp);
fail:    
    if (buf != NULL) {
        free(buf);
    }
    if (asn1 != NULL) {
        ASN1_TYPE_free(asn1);
    }
    if (cnf != NULL) {
        NCONF_free(cnf);
    }
    if (sk != NULL) {
        sk_ASN1_OBJECT_free(sk);
    }
    if (bio != NULL) {
        BIO_free(bio);          // will free up b64 too
    }

    return num;
}

/*
 * free_setval()
 *   - free up any memory allocated when parsing an attribute's SET
 */
void free_setval (setval *freeme)
{
    if (freeme == NULL) {
        return;
    }
    if (freeme->next != NULL) {
        free_setval(freeme->next);
    }
    if (freeme->type == SETVAL_STR) {
        free(freeme->str);
    }
    if (freeme->type == SETVAL_OCTSTR) {
        free(freeme->octstr);
    }
    if (freeme->type == SETVAL_BITSTR) {
        free(freeme->bitstr);
    }
    free(freeme);
    freeme = NULL;
    return;
}

/*
 * get_set()
 *   - parse an ASN.1 SET an extract all the values in it
 */
static setval*
get_set (const unsigned char **p, int len)
{
    unsigned char *ptr = (unsigned char *)*p, *op;
    unsigned char *fin = (unsigned char *)(*p + len);
    int inf, tag, xclass, hl;
    long l, length;
    ASN1_OBJECT *ao = NULL;
    setval *ret = NULL, *next = NULL;
    ASN1_INTEGER *ai = NULL;
    ASN1_OCTET_STRING *os = NULL;

    if (ptr == NULL) {
        return NULL;
    }
    /*
     * this assumes we've already parsed past a V_ASN1_SET
     */
    length = len;
    while (ptr < fin) {
//        dpp_debug(DPP_DEBUG_TRACE, "looping through SET, %d left\n", length);
        op = ptr;
//        debug_buffer(DPP_DEBUG_TRACE, "the SET", ptr, length);
        inf = ASN1_get_object((const unsigned char **)&ptr, &l, &tag, &xclass, length);
        if (inf & 0x80) {
            dpp_debug(DPP_DEBUG_ERR, "bad object for SET!!!\n");
            free_setval(ret);
            return NULL;
        }
        hl = (ptr - op);
//        dpp_debug(DPP_DEBUG_TRACE, "got object for SET (hl = %d)\n", hl);

        /*
         * it's a linked list of setvals...
         */
        if (ret == NULL) {
            if ((ret = (setval *)malloc(sizeof(setval))) == NULL) {
                return NULL;
            }
            ret->type = SETVAL_ERROR;
            ret->next = NULL;
            next = ret;
        } else {
            if ((next->next = (setval *)malloc(sizeof(setval))) == NULL) {
                free_setval(ret);
                return NULL;
            }
            next = next->next;
            next->type = SETVAL_ERROR;
            next->next = NULL;
        }
        /*
         * ...fill it in according to the tag
         */
        if (tag == V_ASN1_OBJECT) {
            ptr = op;
//            debug_buffer(DPP_DEBUG_TRACE, "found ASN1_OBJECT", ptr, length);
            d2i_ASN1_OBJECT(&ao, (const unsigned char **)&ptr, length);
            next->type = SETVAL_NID;
            next->nid = OBJ_obj2nid(ao);
            ASN1_OBJECT_free(ao);
//            dpp_debug(DPP_DEBUG_TRACE, "found an ASN1 OBJECT, nid = %d\n", next->nid);
            ao = NULL;
        } else if ((tag == V_ASN1_PRINTABLESTRING) ||
                   (tag == V_ASN1_T61STRING) ||
                   (tag == V_ASN1_IA5STRING) ||
                   (tag == V_ASN1_VISIBLESTRING) ||
                   (tag == V_ASN1_NUMERICSTRING) ||
                   (tag == V_ASN1_UTF8STRING) ||
                   (tag == V_ASN1_UTCTIME) ||
                   (tag == V_ASN1_GENERALIZEDTIME)) {
//            debug_buffer(DPP_DEBUG_TRACE, "found a STRING", ptr, l);
            next->type = SETVAL_STR;
            if ((next->str = (unsigned char *)malloc(l + 1)) == NULL) {
                free_setval(ret);
                return NULL;
            }
            memset(next->str, 0, l+1);
            memcpy(next->str, ptr, l);
            ptr += l;
        } else if (tag == V_ASN1_INTEGER) {
            ptr = op;
//            debug_buffer(DPP_DEBUG_TRACE, "found a INTEGER", ptr, length);
            d2i_ASN1_UINTEGER(&ai, (const unsigned char **)&ptr, length);
            next->type = SETVAL_INT;
            next->integer = ASN1_INTEGER_get(ai);
            ASN1_INTEGER_free(ai);
            ai = NULL;
        } else if (tag == V_ASN1_OCTET_STRING) {
            ptr = op;
//            debug_buffer(DPP_DEBUG_TRACE, "found a OCTET STRING", ptr, l+hl);
            os = d2i_ASN1_OCTET_STRING(NULL, (const unsigned char **)&ptr, l+hl);
            if ((os != NULL) && (os->length > 0)) {
                next->type = SETVAL_OCTSTR;
                if ((next->octstr = (unsigned char *)malloc(os->length)) == NULL) {
                    free_setval(ret);
                    return NULL;
                }
                memset(next->octstr, 0, os->length);
                memcpy(next->octstr, os->data, os->length);
            }
            if (os != NULL) {
                ASN1_STRING_free(os);
            }
            os = NULL;
            ptr += l;
        }
    }
    if (ret->type == SETVAL_ERROR) {
        free_setval(ret);
        ret = NULL;
    }
    return ret;
}

/*
 * generate a PKCS#10 certificate signing request 
 */
static int
generate_csr (struct candidate *peer, char **csr)
{
    int i, challp_len, pkey_id, tag, xclass, inf, asn1len, csrlen = -1;
    int nid, keylen = 2048, crypto_nid;
    const EVP_MD *md = EVP_sha256();
    const unsigned char *tot, *op;
    unsigned char *savep;
    unsigned char *p, challp[88], cp[64];       /* 88 is base64 of 64 */
    char whoami[20];
    BIO *bio = NULL;
    ASN1_OBJECT *o = NULL;
    const EVP_PKEY_ASN1_METHOD *ameth;
    EVP_PKEY_CTX *pkeyctx = NULL;
    EVP_PKEY *tmp = NULL, *key = NULL;
    EC_GROUP *group = NULL;
    EC_KEY *ec = NULL;
    X509_NAME *subj = NULL;
    X509_REQ *req = NULL;
    long len, length;
    EVP_ENCODE_CTX *ctx;
    setval *values, *value;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    STACK_OF(ASN1_OBJECT) *sk = NULL;
    X509_EXTENSION *ex = NULL;

    if (peer->csrattrs == NULL) {
        *csr = NULL;
        return -1;
    }

    /*
     * start off assuming it's the protocol key
     */
    crypto_nid = dpp_instance.nid;
    md = dpp_instance.hashfcn;

    /*
     * start constructing the X509_REQ 
     */
    if (((req = X509_REQ_new()) == NULL) ||
        (!X509_REQ_set_version(req, 0L))) {
        dpp_debug(DPP_DEBUG_ERR, "cannot create a CSR!\n");
        return -1;
    }
    gethostname(whoami, sizeof(whoami));
    subj = X509_REQ_get_subject_name(req);
    if (!X509_NAME_add_entry_by_txt(subj, "commonName", MBSTRING_ASC,
                                    (unsigned char *)whoami, -1, -1, 0)) {
        dpp_debug(DPP_DEBUG_ERR, "cannot add common name %s\n", whoami);
        return -1;
    }

    /*
     * generate the challengePassword goo
     */
    hkdf_expand(dpp_instance.hashfcn,
                peer->bk, dpp_instance.digestlen,
                (unsigned char *)"CSR challengePassword", strlen("CSR challengePassword"),
                cp, 64);
    challp_len = EVP_EncodeBlock(challp, cp, 64);
    dpp_debug(DPP_DEBUG_TRACE, "adding %d byte challengePassword\n", challp_len);
    /*
     * add the challenge password to the CSR
     */
    X509_REQ_add1_attr_by_NID(req, NID_pkcs9_challengePassword,
                              MBSTRING_UTF8, challp, challp_len);

    length = peer->csrattrs_len;
    p = (unsigned char *)peer->csrattrs;
    tot = p + length;

    /*
     * parse the CSR Attributes we got...
     */
    inf = ASN1_get_object((const unsigned char **)&p, &len, &tag, &xclass, length);
    if (inf & 0x80) {
        /*
         * bad ASN.1, at least generate a CSR and see what happens
         */
        dpp_debug(DPP_DEBUG_ERR, "ASN.1 of CSR Attributes is not well-formed!\n");
        goto gen_csr;
    }
    if (tag != V_ASN1_SEQUENCE) {
        /*
         * ditto
         */
        dpp_debug(DPP_DEBUG_ERR, "ASN.1 of CSR Attributes is not a SEQUENCE OF!\n");
        goto gen_csr;
    }        
    while (p < tot) {
        op = p;
        savep = p;
        inf = ASN1_get_object((const unsigned char **)&p, &len, &tag, &xclass, length);
        if (inf & 0x80) {
            dpp_debug(DPP_DEBUG_ERR, "ASN.1 in SEQUENCE OF is not well-formed\n");
            break;
        }
        /*
         * a SEQUENCE here indicates an attribute...
         */
        if (inf & V_ASN1_CONSTRUCTED) {
            /*
             * parse the attribute, if parsing fails for any reason, skip
             * this attribute and see what's next, don't give up entirely
             */
            op = p + len;   /* mark the end of this attriute */
            savep = p;
            if (tag != V_ASN1_SEQUENCE) {
                dpp_debug(DPP_DEBUG_ERR, "CSR Attr parse: it's not an attribute! Should be a SEQUENCE here\n");
                goto parse_fail;
            }
            values = NULL;
            inf = ASN1_get_object((const unsigned char **)&p, &len, &tag, &xclass, length);
            if (inf & 0x80) {
                dpp_debug(DPP_DEBUG_ERR, "CSR Attr parse: bad asn.1 for attribute\n");
                goto parse_fail;
            }
            /*
             * an attribute starts out with an object...
             */
            if (tag != V_ASN1_OBJECT) {
                dpp_debug(DPP_DEBUG_ERR, "CSR Attr parse: it's not an attribute! Should be an object here\n");
                goto parse_fail;
            }
            d2i_ASN1_OBJECT(&o, (const unsigned char **)&savep, length);
            nid = OBJ_obj2nid(o);
            ASN1_OBJECT_free(o);
            o = NULL;
            p = savep;
            /*
             * ...and then a SET...
             */
            inf = ASN1_get_object((const unsigned char **)&p, &len, &tag, &xclass, length);
            if (inf & 0x80) {
                dpp_debug(DPP_DEBUG_ERR, "CSR Attr parse: bad asn.1 for SET in attribute\n");
                goto parse_fail;
            }
            if (!(inf & V_ASN1_CONSTRUCTED) || (tag != V_ASN1_SET)) {
                dpp_debug(DPP_DEBUG_ERR, "CSR Attr parse: it's not an attribute! Should be a SET here\n");
                goto parse_fail;
            }
            /*
             * ...and all the values in the SET
             */
            if ((values = get_set((const unsigned char **)&p, len)) == NULL) {
                dpp_debug(DPP_DEBUG_ERR, "CSR Attr parse: couldn't get values from set!\n");
                goto parse_fail;
            }
            dpp_debug(DPP_DEBUG_TRACE, "CSR Attr parse: got a SET OF attributes...");
            switch (nid) {
                /*
                 * depending on the attribute's object (the nid), parse through
                 * whatever was in the set looking for something that makes sense
                 * for this attribute. We'll ignore stuff in the set that doesn't
                 * make sense instead of rejecting the attribute.
                 */
                case NID_rsaEncryption:
                    /*
                     * for RSA, look for a key length
                     */
                    dpp_debug(DPP_DEBUG_TRACE, " nid for RSA encryption\n");
                    for (value = values; value != NULL; value = value->next) {
                        if (value->type == SETVAL_INT) {
                            crypto_nid = nid;
                            keylen = value->integer;
                            dpp_debug(DPP_DEBUG_TRACE, " RSA encryption, key length: %d\n", keylen);
                            break;
                        }
                    }
                    break;
                case NID_X9_62_id_ecPublicKey:
                    /*
                     * for EC, look for a supported curve
                     */
                    dpp_debug(DPP_DEBUG_TRACE, " nid for ecPublicKey\n");
                    for (value = values; value != NULL; value = value->next) {
                        if ((value->type == SETVAL_NID) &&
                            ((value->nid == NID_secp384r1)  ||
                             (value->nid == NID_secp521r1) ||
#ifdef HAS_BRAINPOOL
                             (value->nid == NID_brainpoolP256r1) ||
                             (value->nid == NID_brainpoolP384r1) ||
                             (value->nid == NID_brainpoolP512r1) ||
#endif  /* HAS_BRAINPOOL */
                             (value->nid == NID_X9_62_prime256v1) ||
                             (value->nid == NID_secp256k1))) {
                            crypto_nid = value->nid;
                            dpp_debug(DPP_DEBUG_TRACE, " an elliptic curve, nid = %d\n", crypto_nid);
                            break;
                        }
                    }
                    break;
                case NID_pseudonym:
                case NID_friendlyName:
                case NID_pkcs9_unstructuredName:
                    /*
                     * add some additional name constructs to the extension
                     */
                    if (exts == NULL) {
                        if ((exts = sk_X509_EXTENSION_new_null()) == NULL) {
                            break;
                        }
                    }
                    dpp_debug(DPP_DEBUG_TRACE, " nid for additional naming\n");
                    for (value = values; value != NULL; value = value->next) {
                        ASN1_OCTET_STRING *os;
                        
                        if (value->type == SETVAL_STR) {
                            if ((os = ASN1_OCTET_STRING_new()) == NULL) {
                                break;
                            }
                            if (!ASN1_OCTET_STRING_set(os, (unsigned char *)whoami, strlen(whoami))) {
                                break;
                            }
                            ex = X509_EXTENSION_create_by_NID(NULL, value->nid, 0, os);
                            sk_X509_EXTENSION_push(exts, ex);
                            dpp_debug(DPP_DEBUG_TRACE, " a string for %s: %s\n", 
                                  nid == NID_pseudonym ? "pseudonym" : 
                                  nid == NID_friendlyName ? "friendly name" : "unstructuredName", 
                                  whoami);
                            break;
                        }
                    }
                    break;
                case NID_ext_req:
                    /*
                     * an explicit extension request...
                     */
                    if (exts == NULL) {
                        if ((exts = sk_X509_EXTENSION_new_null()) == NULL) {
                            break;
                        }
                    }
                    dpp_debug(DPP_DEBUG_TRACE, " an extension request:\n");
                    for (value = values; value != NULL; value = value->next) {
                        ASN1_OCTET_STRING *os;
                        
                        if (value->type == SETVAL_NID) {
                            switch (value->nid) {
                                /*
                                 * fill in actual values, don't feel like plumbing options in from
                                 * the CLI....
                                 */
                                case NID_serialNumber:
                                    if ((os = ASN1_OCTET_STRING_new()) == NULL) {
                                        break;
                                    }
                                    if (!ASN1_OCTET_STRING_set(os, (unsigned char *)"SMERSH-7474", strlen("SMERSH-7474"))) {
                                        break;
                                    }
                                    ex = X509_EXTENSION_create_by_NID(NULL, value->nid, 0, os);
                                    sk_X509_EXTENSION_push(exts, ex);
                                    dpp_debug(DPP_DEBUG_TRACE, "\tfor serial number\n");
                                    ASN1_OCTET_STRING_free(os);
                                    break;
                                case NID_favouriteDrink:
                                    if ((os = ASN1_OCTET_STRING_new()) == NULL) {
                                        break;
                                    }
                                    if (!ASN1_OCTET_STRING_set(os, (unsigned char *)"le vrai pastis de Marsaille",
                                                               strlen("le vrai pastis de Marsaille"))) {
                                        break;
                                    }
                                    ex = X509_EXTENSION_create_by_NID(NULL, value->nid, 0, os);
                                    sk_X509_EXTENSION_push(exts, ex);
                                    dpp_debug(DPP_DEBUG_TRACE, "\tfor favorite drink\n");
                                    ASN1_OCTET_STRING_free(os);
                                    break;
                                default:
                                    dpp_debug(DPP_DEBUG_TRACE, "\tNID = \n", value->nid);
                                    break;
                            }
                        }
                    }
                    break;
                case NID_ext_key_usage:
                    dpp_debug(DPP_DEBUG_TRACE, " an extended key usage request:\n");
                    if (exts == NULL) {
                        if ((exts = sk_X509_EXTENSION_new_null()) == NULL) {
                            break;
                        }
                    }
                    if ((sk = sk_ASN1_OBJECT_new_null()) == NULL) {
                        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
                        break;
                    }
                    /*
                     * go through the SET OF and see if there's anything
                     * we understand. If so, add it to the extensions
                     */
                    for (value = values; value != NULL; value = value->next) {
                        if (value->type == SETVAL_NID) {
                            switch (value->nid) {
                                case NID_server_auth:
                                case NID_client_auth:
                                case NID_ipsecTunnel:
                                    if ((o = OBJ_nid2obj(value->nid)) != NULL) {
                                        sk_ASN1_OBJECT_push(sk, o);
                                    }
                                    break;
                                default:
                                    break;
                            }
                        }
                    }
                    /*
                     * don't make these critical
                     */
                    if ((ex = X509V3_EXT_i2d(NID_ext_key_usage, 0, sk)) != NULL) {
                        sk_X509_EXTENSION_push(exts, ex);
                    }
                    break;
                    /*
                     * add cases here for more NIDs that we understand
                     */
                default:
                    dpp_debug(DPP_DEBUG_TRACE, "unknown attribute...skipping\n");
                    goto parse_fail;
            }
            free_setval(values);
parse_fail:
            /*
             * end of attribute...next!
             */
            p = (unsigned char *)op;
            continue;
        } else if (tag == V_ASN1_OBJECT) {
            dpp_debug(DPP_DEBUG_TRACE, "an object, not an attribute\n");
            /*
             * not an attribute, just another object in the SEQUENCE, do our best
             */
            if (d2i_ASN1_OBJECT(&o, (const unsigned char **)&savep, length) == NULL) {
                dpp_debug(DPP_DEBUG_TRACE, "failed to get the object goo\n");
            }
            nid = OBJ_obj2nid(o);
            ASN1_OBJECT_free(o);
            o = NULL;
            p = savep;
            switch (nid) {
                case NID_serialNumber:
                    /*
                     * add some printable string to the CSR
                     */
                    dpp_debug(DPP_DEBUG_TRACE, "a nid for serial number\n");
                    break;
                case NID_pkcs9_challengePassword:   /* we always send this */
                    dpp_debug(DPP_DEBUG_TRACE, "a nid for challengePassword\n");
                    break;
                case NID_sha256WithRSAEncryption:
                    crypto_nid = NID_rsaEncryption;
                    dpp_debug(DPP_DEBUG_TRACE, "a nid for sha256withRSAEncryption\n");
                    md = EVP_sha256();
                    break;
                case NID_sha384WithRSAEncryption:
                    crypto_nid = NID_rsaEncryption;
                    dpp_debug(DPP_DEBUG_TRACE, "a nid for sha384withRSAEncryption\n");
                    md = EVP_sha384();
                    break;
                case NID_sha512WithRSAEncryption:
                    crypto_nid = NID_rsaEncryption;
                    dpp_debug(DPP_DEBUG_TRACE, "a nid for sha512withRSAEncryption\n");
                    md = EVP_sha512();
                    break;
                case NID_ecdsa_with_SHA256:
                    /*
                     * if we get a ecdsa_with_SHAXYZ then set the curve
                     * to be something appropriate for the hash if it's
                     * dumb.
                     */
                    dpp_debug(DPP_DEBUG_TRACE, "a nid for ecdsa with sha256\n");
                    if (crypto_nid == NID_rsaEncryption) {
                        crypto_nid = NID_X9_62_prime256v1;
                    }
                    md = EVP_sha256();
                    break;
                case NID_ecdsa_with_SHA384:
                    dpp_debug(DPP_DEBUG_TRACE, "a nid for ecdsa with sha384\n");
                    if (crypto_nid == NID_rsaEncryption) {
                        crypto_nid = NID_secp384r1;
                    }
                    md = EVP_sha384();
                    break;
                case NID_ecdsa_with_SHA512:
                    dpp_debug(DPP_DEBUG_TRACE, "a nid for ecdsa with sha512\n");
                    if (crypto_nid == NID_rsaEncryption) {
                        crypto_nid = NID_secp521r1;
                    }
                    md = EVP_sha512();
                    break;
                case NID_secp384r1:
                case NID_secp521r1:
                case NID_secp256k1:
                case NID_X9_62_prime256v1:
                    dpp_debug(DPP_DEBUG_TRACE, "a nid for an elliptic curve\n");
                    crypto_nid = nid;
                    break;
                case NID_sha256:
                    dpp_debug(DPP_DEBUG_TRACE, "a nid for sha256\n");
                    md = EVP_sha256();
                    break;
                case NID_sha384:
                    dpp_debug(DPP_DEBUG_TRACE, "a nid for sha384\n");
                    md = EVP_sha384();
                    break;
                case NID_sha512:
                    dpp_debug(DPP_DEBUG_TRACE, "a nid for sha512\n");
                    md = EVP_sha512();
                    break;
                default:
                    dpp_debug(DPP_DEBUG_TRACE, "a nid for something I don't understand %d\n", nid);
            }
        } else {
            dpp_debug(DPP_DEBUG_ERR, "not a SEQUENCE OF objects and attributes!\n");
            p += len;
        }
    }
gen_csr:
    /*
     * if we got extensions, then add them to the CSR and free them up
     */
    if (exts != NULL) {
        X509_REQ_add_extensions(req, exts);
        if (sk != NULL) {
            sk_ASN1_OBJECT_pop_free(sk, ASN1_OBJECT_free);
        }
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        exts = NULL;
    }
    /*
     * if we were told to use a different public key then generate it
     */
    if (crypto_nid != dpp_instance.nid) {
        if (crypto_nid == NID_rsaEncryption) {
            dpp_debug(DPP_DEBUG_PKI, "generating an RSA key for CSR...\n");
            /*
             * rsa of the specified length
             */
            ameth = EVP_PKEY_asn1_find_str(NULL, "rsa", -1);
            EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL, ameth);
            pkeyctx = EVP_PKEY_CTX_new_id(pkey_id, NULL);
            if (EVP_PKEY_keygen_init(pkeyctx) < 1) {
                dpp_debug(DPP_DEBUG_ERR, "can't initialize key generation for RSA\n");
                return -1;
            }
            EVP_PKEY_CTX_set_rsa_keygen_bits(pkeyctx, keylen);
        } else {
            dpp_debug(DPP_DEBUG_PKI, "generating an ECC key for CSR...\n");
            /*
             * generate an EC keypair for the specified group
             */
            if ((group = EC_GROUP_new_by_curve_name(crypto_nid)) == NULL) {
                dpp_debug(DPP_DEBUG_ERR, "unable to create curve group!\n");
                return -1;
            }
            EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
            EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_UNCOMPRESSED);
            if ((ec = EC_KEY_new()) == NULL) {
                dpp_debug(DPP_DEBUG_ERR, "unable to create an EC_KEY!\n");
                return -1;
            }
            if (EC_KEY_set_group(ec, group) == 0) {
                dpp_debug(DPP_DEBUG_ERR, "unable to set group to  PKEY!\n");
                return -1;
            }
            if (!EC_KEY_generate_key(ec)) {
                dpp_debug(DPP_DEBUG_ERR, "unable to generate PKEY!\n");
                return -1;
            }
            /*
             * assign EC keypair to an EVP_PKEY and then use that to make
             * an EVP_PKEY_CTX
             */
            if ((tmp = EVP_PKEY_new()) == NULL) {
                dpp_debug(DPP_DEBUG_ERR, "unable to create PKEY!\n");
                return -1;
            }
            EVP_PKEY_assign(tmp, EVP_PKEY_EC, ec);
            pkeyctx = EVP_PKEY_CTX_new(tmp, NULL);
            EVP_PKEY_free(tmp);
            EC_GROUP_free(group);
        }
        /*
         * we have an EVP_PKEY_CTX now for our desired public key type, generate!
         */
        if (EVP_PKEY_keygen_init(pkeyctx) < 1) {
            dpp_debug(DPP_DEBUG_ERR, "unable to initiate keygen procedure!\n");
            goto csr_fail;
        }
        if (EVP_PKEY_keygen(pkeyctx, &key) < 1) {
            dpp_debug(DPP_DEBUG_ERR, "unable to generate keypair!\n");
            goto csr_fail;
        }
        EVP_PKEY_CTX_free(pkeyctx); /* will free ec too, if used */
        if ((bio = BIO_new_file("key_for_cert.pem", "w")) != NULL) {
            PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
        }
        BIO_free(bio);
        bio = NULL;
        /*
         * put the key in the request and sign the request
         */
        X509_REQ_set_pubkey(req, key);
        if (!X509_REQ_sign(req, key, md)) {
            dpp_debug(DPP_DEBUG_ERR, "can't sign CSR with new key!\n");
            goto csr_fail;
        }
    } else {
        EC_KEY *protodup;
        
        dpp_debug(DPP_DEBUG_PKI, "using bootstrapping key for CSR...\n");
        /*
         * need an EVP_PKEY_CTX with our protocol key to do the signing
         */
        if ((tmp = EVP_PKEY_new()) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "unable to create PKEY!\n");
            goto csr_fail;
        }
        if ((protodup = EC_KEY_dup(peer->my_proto)) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "unable to duplicate protocol key for CSR\n");
            goto csr_fail;
        }

        EVP_PKEY_assign(tmp, EVP_PKEY_EC, protodup);
        if ((bio = BIO_new_file("key_for_cert.pem", "w")) != NULL) {
            PEM_write_bio_PrivateKey(bio, tmp, NULL, NULL, 0, NULL, NULL);
        }
        BIO_free(bio);
        bio = NULL;
        X509_REQ_set_pubkey(req, tmp);
        if (!X509_REQ_sign(req, tmp, md)) {
            dpp_debug(DPP_DEBUG_ERR, "can't sign CSR with protocol key!\n");
            goto csr_fail;
        }
        EVP_PKEY_free(tmp);     // this will free protodup too
    }

    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to create another bio!\n");
        goto csr_fail;
    }

    i2d_X509_REQ_bio(bio, req);
    asn1len = BIO_get_mem_data(bio, &p);

    if ((*csr = malloc(2*asn1len)) == NULL) {
        goto csr_fail;
    }

    if ((ctx = EVP_ENCODE_CTX_new()) == NULL) {
        goto csr_fail;
    }
    /*
     * base64 encode the request
     */
    EVP_EncodeInit(ctx);
    EVP_EncodeUpdate(ctx, (unsigned char *)*csr, &i, p, asn1len);
    csrlen = i;
    EVP_EncodeFinal(ctx, (unsigned char *)&((*csr)[i]), &i);
    csrlen += i;
    EVP_ENCODE_CTX_free(ctx);
        
    (*csr)[csrlen] = '\0';
    dpp_debug(DPP_DEBUG_TRACE, "CSR is %d chars:\n%s\n", csrlen, *csr);
csr_fail:
    X509_REQ_free(req);
    if (key != NULL) {
        EVP_PKEY_free(key);
    }
    if (bio != NULL) {
        BIO_free(bio);
    }
    return csrlen;

}

//----------------------------------------------------------------------
// wpa_supplicant support-- write out a .conf file for various AKMs
//----------------------------------------------------------------------

/*
 * dump the connector and network access key in aformat suitable for 
 * hostapd/wpa_supplicant-- this is the stuff to use to connect.
 */
static void
dump_key_con (struct candidate *peer, char *ssid, int ssidlen)
{
    FILE *fp;
    char *buf;
    unsigned char *asn1, data[1024];
    char conffile[45], netname[33];
    int buflen, asn1len, i;
    BIO *bio;

    /*
     * write out the connector...
     */
    if ((fp = fopen("connector.pem", "w")) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to store the connector!\n");
        return;
    }
    if ((buf = malloc(connector_len + 1)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to copy the connector!\n");
        return;
    }
    memcpy(buf, connector, connector_len);
    buf[connector_len] = '\0';
    fprintf(fp, "%s\n", buf);
    fclose(fp);
    dpp_debug(DPP_DEBUG_TRACE, "wrote %d byte connector\n", connector_len);

    if ((bio = BIO_new(BIO_s_file())) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to save network access key!\n");
        free(buf);
        return;
    }
    if ((fp = fopen("netaccesskey", "w")) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to store the network access key!\n");
        free(buf);
        return;
    }
    BIO_set_fp(bio, fp, BIO_CLOSE);
    buflen = PEM_write_bio_ECPrivateKey(bio, netaccesskey, NULL, NULL, 0, NULL, NULL);
    dpp_debug(DPP_DEBUG_TRACE, "%s netaccesskey\n", buflen > 0 ? "wrote" : "didn't write");
    fflush(fp);
    BIO_free(bio);

    /*
     * if we're just provisioning the connector for configuration issues and
     * not for network access then we're done here.
     */
    if ((ssid == NULL) || (ssidlen == 0)) {
        free(buf);
        return;
    }

    memset(netname, 0, sizeof(netname));
    memset(conffile, 0, sizeof(conffile));
    if (ssid[0] == '*' || ssidlen == 1) {
        strcpy(netname, "*");
        strcpy(conffile, "wildcard_dpp.conf");
    } else {
        memcpy(netname, ssid, ssidlen);
        snprintf(conffile, sizeof(conffile), "%s_dpp.conf", netname);
    }
    if ((fp = fopen(conffile, "w")) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to create wpa_supplicant config file!\n");
        free(buf);
        return;
    }

    fprintf(fp, "ctrl_interface=/var/run/wpa_supplicant\n");
    fprintf(fp, "ctrl_interface_group=0\n");
    fprintf(fp, "update_config=1\n");
    fprintf(fp, "pmf=2\n");
    fprintf(fp, "dpp_config_processing=2\n");
    fprintf(fp, "network={\n");
    fprintf(fp, "\tssid=\"%s\"\n", netname);
    fprintf(fp, "\tkey_mgmt=DPP\n");
    fprintf(fp, "\tieee80211w=2\n");
    fprintf(fp, "\tdpp_connector=\"%s\"\n", buf);

    fprintf(fp, "\tdpp_netaccesskey=");
    memset(data, 0, sizeof(data));
    asn1 = data;
    asn1len = i2d_ECPrivateKey(netaccesskey, &asn1);
    for (i = 0; i < asn1len; i++) {
        fprintf(fp, "%02x", data[i]);
    }

    fprintf(fp, "\n\tdpp_csign=");
    memset(data, 0, sizeof(data));
    asn1 = data;
    asn1len = i2d_EC_PUBKEY(configurator_signkey, &asn1);
    for (i = 0; i < asn1len; i++) {
        fprintf(fp, "%02x", data[i]);
    }
    fprintf(fp, "\n}\n");
    fclose(fp);
    dpp_debug(DPP_DEBUG_TRACE, "created %s for wpa_supplicant configuration\n", conffile);

    free(buf);
}

static void
dump_pwd_con (char *ssid, int ssidlen, char *pwd, int sae)
{
    FILE *fp;
    char conffile[45], netname[33];

    memset(netname, 0, sizeof(netname));
    memset(conffile, 0, sizeof(conffile));
    if (ssid == NULL || ssidlen == 0) {
        strcpy(netname, "*");
        snprintf(conffile, sizeof(conffile), "wildcard_%s.conf", sae ? "sae" : "psk");
    } else {
        memcpy(netname, ssid, ssidlen);
        snprintf(conffile, sizeof(conffile), "%s_%s.conf", netname, sae ? "sae" : "psk");
    }
    if ((fp = fopen(conffile, "w")) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to create wpa_supplicant config file!\n");
        return;
    }

    fprintf(fp, "ctrl_interface=/var/run/wpa_supplicant\n");
    fprintf(fp, "ctrl_interface_group=0\n");
    fprintf(fp, "update_config=1\n");
    if (sae) {
        fprintf(fp, "pmf=2\n");
    }
    fprintf(fp, "network={\n");
    fprintf(fp, "\tssid=\"%s\"\n", netname);
    fprintf(fp, "\tproto=RSN\n");
    fprintf(fp, "\tkey_mgmt=%s\n", sae ? "SAE" : "WPA-PSK");
    fprintf(fp, "\tpsk=\"%s\"\n", pwd);
    fprintf(fp, "\tpairwise=CCMP\n");
    fprintf(fp, "\tgroup=CCMP\n");
    fprintf(fp, "}\n");
    fclose(fp);
    dpp_debug(DPP_DEBUG_TRACE, "created %s for wpa_supplicant configuration\n", conffile);

    return;
}

static void
dump_cert_con (char *ssid, int ssidlen, char *p7, int p7len, char *san, int sanlen)
{
    FILE *fp;
    char conffile[45], netname[33];

    memset(netname, 0, sizeof(netname));
    memset(conffile, 0, sizeof(conffile));
    if (ssid == NULL || ssidlen == 0) {
        strcpy(netname, "*");
        snprintf(conffile, sizeof(conffile), "wildcard_dot1x.conf");
    } else {
        memcpy(netname, ssid, ssidlen);
        snprintf(conffile, sizeof(conffile), "%s_dot1x.conf", netname);
    }
    if ((fp = fopen(conffile, "w")) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to create wpa_supplicant config file!\n");
        return;
    }

    fprintf(fp, "ctrl_interface=/var/run/wpa_supplicant\n");
    fprintf(fp, "ctrl_interface_group=0\n");
    fprintf(fp, "update_config=1\n");
    fprintf(fp, "pmf=2\n");
    fprintf(fp, "network={\n");
    fprintf(fp, "\tssid=\"%s\"\n", netname);
    fprintf(fp, "\tproto=RSN\n");
    fprintf(fp, "\tkey_mgmt=IEEE8021X\n");
    fprintf(fp, "\teap=TLS\n");
    fprintf(fp, "\tclient_cert=\"mycert0.pem\"\n");
    fprintf(fp, "\tprivate_key=\"key_for_cert.pem\"\n");
    fprintf(fp, "\tca_cert=\"cacert0.pem\"\n");
    fprintf(fp, "\tpairwise=CCMP\n");
    fprintf(fp, "\tgroup=CCMP\n");
    fprintf(fp, "}\n");
    fclose(fp);
    dpp_debug(DPP_DEBUG_TRACE, "created %s for wpa_supplicant configuration\n", conffile);

    return;
}

//----------------------------------------------------------------------
// DPP configuration exchange routines
//----------------------------------------------------------------------


static int
send_dpp_config_result (struct candidate *peer, unsigned char status)
{
    siv_ctx ctx;
    TLV *wraptlv, *tlv;

    dpp_debug(DPP_DEBUG_TRACE, "sending dpp config result\n");
    memset(peer->buffer, 0, sizeof(peer->buffer));
    peer->bufferlen = 0;

    wraptlv = (TLV *)peer->buffer;
    wraptlv->type = ieee_order(WRAPPED_DATA);
    tlv = (TLV *)(wraptlv->value + AES_BLOCK_SIZE);
    tlv = TLV_set_tlv(tlv, DPP_STATUS, 1, &status);
    tlv = TLV_set_tlv(tlv, ENROLLEE_NONCE, dpp_instance.noncelen, peer->enonce);
    
    ieeeize_hton_attributes(wraptlv->value + AES_BLOCK_SIZE,
                            (int)((unsigned char *)tlv - (unsigned char *)(wraptlv->value + AES_BLOCK_SIZE)));

    setup_dpp_action_frame(peer, DPP_CONFIG_RESULT);
    switch(dpp_instance.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_512);
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", dpp_instance.digestlen);
    }
    peer->bufferlen = (int)((unsigned char *)tlv - peer->buffer);
    wraptlv->length = ieee_order(peer->bufferlen - sizeof(TLV));

    siv_encrypt(&ctx, wraptlv->value + AES_BLOCK_SIZE, wraptlv->value + AES_BLOCK_SIZE,
                (unsigned char *)tlv - ((unsigned char *)wraptlv->value + AES_BLOCK_SIZE),
                wraptlv->value,
                2, peer->frame, sizeof(dpp_action_frame), peer->buffer, 0);
    
    send_dpp_action_frame(peer);

    return 1;
}
        
static int
generate_dpp_config_resp_frame (struct candidate *peer, unsigned char status)
{
    siv_ctx ctx;
    TLV *tlv, *wraptlv;
    unsigned char burlx[256], burly[256], kid[KID_LENGTH];
    unsigned char conn[1024], *bn = NULL, *ptr;
    char confresp[4096];
    int sofar = 0, offset, burllen, nid;
    BIGNUM *x = NULL, *y = NULL, *signprime = NULL;
    const EC_POINT *signpub, *newpub;
    const EC_GROUP *signgroup = NULL;
    unsigned char *encrypt_ptr = NULL;
    unsigned short wrapped_len = 0, grp;
    time_t t;
    struct tm *bdt;
    struct cpolicy *cp;

    memset(peer->buffer, 0, sizeof(peer->buffer));
    peer->bufferlen = 0;
    
    tlv = (TLV *)peer->buffer;
    wraptlv = TLV_set_tlv(tlv, DPP_STATUS, 1, &status);
    wraptlv->type = WRAPPED_DATA;
    tlv = (TLV *)(wraptlv->value + AES_BLOCK_SIZE);
    encrypt_ptr = (unsigned char *)tlv;
    tlv = TLV_set_tlv(tlv, ENROLLEE_NONCE, dpp_instance.noncelen, peer->enonce);

    if (status == STATUS_OK) {
        /*
         * if we can't generate a connector then indicate configuration failure
         */
        if (dpp_instance.newgroup) {
            if ((peer->peernewproto == NULL) ||
                generate_connector(conn, sizeof(conn),
                                   (EC_GROUP *)EC_KEY_get0_group(peer->mynewproto),
                                   peer->peernewproto, peer->enrollee_role,
                                   dpp_instance.signkey, bnctx) < 0) {
                dpp_debug(DPP_DEBUG_ERR, "unable to create a connector!\n");
                status = STATUS_CONFIGURE_FAILURE;
                goto problemo;
            }
        } else {
            if (generate_connector(conn, sizeof(conn), (EC_GROUP *)dpp_instance.group,
                                   peer->peer_proto, peer->enrollee_role,
                                   dpp_instance.signkey, bnctx) < 0) {
                dpp_debug(DPP_DEBUG_ERR, "unable to create a connector!\n");
                status = STATUS_CONFIGURE_FAILURE;
                goto problemo;
            }
        }
        if (((signpub = EC_KEY_get0_public_key(dpp_instance.signkey)) == NULL) ||
            ((signgroup = EC_KEY_get0_group(dpp_instance.signkey)) == NULL) ||
            (get_kid_from_point(kid, signgroup, signpub, bnctx) < 0)) {
            dpp_debug(DPP_DEBUG_ERR, "unable to get kid of public signing key!\n");
            status = STATUS_CONFIGURE_FAILURE;
            goto problemo;
        } 
        if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
            ((signprime = BN_new()) == NULL) ||
            !EC_GROUP_get_curve_GFp(signgroup, signprime, NULL, NULL, bnctx) ||
            !EC_POINT_get_affine_coordinates_GFp(signgroup, signpub, x, y, bnctx)) {
            dpp_debug(DPP_DEBUG_ERR, "unable to get coordinates of public signing key!\n");
            status = STATUS_CONFIGURE_FAILURE;
            goto problemo;
        } 
        if ((bn = (unsigned char *)malloc(BN_num_bytes(signprime))) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "unable to alloc memory for public signing key points!\n");
            status = STATUS_CONFIGURE_FAILURE;
            goto problemo;
        }
        memset(bn, 0, BN_num_bytes(signprime));
        offset = BN_num_bytes(signprime) - BN_num_bytes(x);
        BN_bn2bin(x, bn + offset);
        if ((burllen = base64urlencode(burlx, bn, BN_num_bytes(signprime))) < 0) {
            dpp_debug(DPP_DEBUG_ERR, "unable to b64url encode x!\n");
            status = STATUS_CONFIGURE_FAILURE;
            goto problemo;
        }
        burlx[burllen] = '\0';
        memset(bn, 0, BN_num_bytes(signprime));
        offset = BN_num_bytes(signprime) - BN_num_bytes(y);
        BN_bn2bin(y, bn + offset);
        if ((burllen = base64urlencode(burly, bn, BN_num_bytes(signprime))) < 0) {
            dpp_debug(DPP_DEBUG_ERR, "unable to b64url encode y!\n");
            status = STATUS_CONFIGURE_FAILURE;
            goto problemo;
        }
        burly[burllen] = '\0';
    }
problemo:
    /*
     * if we're go then cons up a configuration object
     */
    sofar = 0;
    switch (status) {
        case STATUS_OK:
            /*
             * make the configuration objects are good for 1 year (tm_year + 1901) from right now
             */
            t = time(NULL);
            bdt = gmtime(&t);
            nid = EC_GROUP_get_curve_name(signgroup);
            TAILQ_FOREACH(cp, &cpolicies, entry) {
                if (strcmp(cp->akm, "dpp") == 0) {
                    sofar = snprintf(confresp, sizeof(confresp)-1,
                                     "{\"wi-fi_tech\":\"infra\",\"discovery\":{\"ssid\":\"%s\"},"
                                     "\"cred\":{\"akm\":\"%s\","
                                     "\"signedConnector\":"
                                     "\"%s\",\"csign\":{\"kty\":\"EC\",\"crv\":\"%s\","
                                     "\"x\":\"%s\",\"y\":\"%s\",\"kid\":\"%s\"},"
                                     "\"ppKey\":{\"kty\":\"EC\",\"crv\":\"%s\","
                                     "\"x\":\"%s\",\"y\":\"%s\",\"kid\":\"%s\"},"
                                     "\"expiry\":\"%04d-%02d-%02dT%02d:%02d:%02d\"}}",
                                     cp->ssid, cp->akm, conn,
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
                } else if (strcmp(cp->akm, "sae") == 0) {
                    if (peer->version > 1) {
                        sofar = snprintf(confresp, sizeof(confresp)-1,
                                         "{\"wi-fi_tech\":\"infra\",\"discovery\":{\"ssid\":\"%s\"},"
                                         "\"cred\":{\"akm\":\"%s\","
                                         "\"pass\":\"%s\","
                                         "\"signedConnector\":"
                                         "\"%s\",\"csign\":{\"kty\":\"EC\",\"crv\":\"%s\","
                                         "\"x\":\"%s\",\"y\":\"%s\",\"kid\":\"%s\"},"
                                         "\"ppKey\":{\"kty\":\"EC\",\"crv\":\"%s\","
                                         "\"x\":\"%s\",\"y\":\"%s\",\"kid\":\"%s\"},"
                                         "\"expiry\":\"%04d-%02d-%02dT%02d:%02d:%02d\"}}",
                                         cp->ssid, cp->akm, cp->auxdata, conn,
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
                    } else {
                        sofar = snprintf(confresp, sizeof(confresp)-1,
                                         "{\"wi-fi_tech\":\"infra\",\"discovery\":{\"ssid\":\"%s\"},"
                                         "\"cred\":{\"akm\":\"%s\","
                                         "\"pass\":\"%s\","
                                         "\"expiry\":\"%04d-%02d-%02dT%02d:%02d:%02d\"}}",
                                         cp->ssid, cp->akm, cp->auxdata,
                                         bdt->tm_year+1901, bdt->tm_mon, bdt->tm_mday,
                                         bdt->tm_hour, bdt->tm_min, bdt->tm_sec);
                    }
                } else if (strcmp(cp->akm, "psk") == 0) {
                    if (peer->version > 1) {
                        sofar = snprintf(confresp, sizeof(confresp)-1,
                                         "{\"wi-fi_tech\":\"infra\",\"discovery\":{\"ssid\":\"%s\"},"
                                         "\"cred\":{\"akm\":\"%s\","
                                         "\"pass\":\"%s\","
                                         "\"signedConnector\":"
                                         "\"%s\",\"csign\":{\"kty\":\"EC\",\"crv\":\"%s\","
                                         "\"x\":\"%s\",\"y\":\"%s\",\"kid\":\"%s\"},"
                                         "\"ppKey\":{\"kty\":\"EC\",\"crv\":\"%s\","
                                         "\"x\":\"%s\",\"y\":\"%s\",\"kid\":\"%s\"},"
                                         "\"expiry\":\"%04d-%02d-%02dT%02d:%02d:%02d\"}}",
                                         cp->ssid, cp->akm, cp->auxdata, conn,
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
                                 
                    } else {
                        sofar = snprintf(confresp, sizeof(confresp)-1,
                                         "{\"wi-fi_tech\":\"infra\",\"discovery\":{\"ssid\":\"%s\"},"
                                         "\"cred\":{\"akm\":\"%s\","
                                         "\"pass\":\"%s\","
                                         "\"expiry\":\"%04d-%02d-%02dT%02d:%02d:%02d\"}}",
                                         cp->ssid, cp->akm, cp->auxdata,
                                         bdt->tm_year+1901, bdt->tm_mon, bdt->tm_mday,
                                         bdt->tm_hour, bdt->tm_min, bdt->tm_sec);
                    }
                } else if (strcmp(cp->akm, "dot1x") == 0) {
                    if (peer->p7len == 0) {
                        dpp_debug(DPP_DEBUG_ERR, "generating a config object for enterprise but no p7!\n");
                        break;
                    }
                    /*
                     * enterprise credentials are only v2 so no need to check version
                     */
                    if (dpp_instance.cacert_len) {
                        sofar = snprintf(confresp, sizeof(confresp)-1,
                                         "{\"wi-fi_tech\":\"infra\",\"discovery\":{\"ssid\":\"%s\"},"
                                         "\"cred\":{\"akm\":\"%s\","
                                         "\"entCreds\":{\"certBag\":\"%s\","
                                         "\"caCerts\":\"%s\",\"trustedEapServerName\":\"%s\"},"
                                         "\"signedConnector\":"
                                         "\"%s\",\"csign\":{\"kty\":\"EC\",\"crv\":\"%s\","
                                         "\"x\":\"%s\",\"y\":\"%s\",\"kid\":\"%s\"},"
                                         "\"ppKey\":{\"kty\":\"EC\",\"crv\":\"%s\","
                                         "\"x\":\"%s\",\"y\":\"%s\",\"kid\":\"%s\"},"
                                         "\"expiry\":\"%04d-%02d-%02dT%02d:%02d:%02d\"}}",
                                         cp->ssid, cp->akm, peer->p7, dpp_instance.cacert, cp->auxdata, conn,
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
                    } else {
                        sofar = snprintf(confresp, sizeof(confresp)-1,
                                         "{\"wi-fi_tech\":\"infra\",\"discovery\":{\"ssid\":\"%s\"},"
                                         "\"cred\":{\"akm\":\"%s\","
                                         "\"entCreds\":{\"certBag\":\"%s\"},"
                                         "\"signedConnector\":"
                                         "\"%s\",\"csign\":{\"kty\":\"EC\",\"crv\":\"%s\","
                                         "\"x\":\"%s\",\"y\":\"%s\",\"kid\":\"%s\"},"
                                         "\"ppKey\":{\"kty\":\"EC\",\"crv\":\"%s\","
                                         "\"x\":\"%s\",\"y\":\"%s\",\"kid\":\"%s\"},"
                                         "\"expiry\":\"%04d-%02d-%02dT%02d:%02d:%02d\"}}",
                                         cp->ssid, cp->akm, peer->p7, conn,
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
                    }
                } else {
                    dpp_debug(DPP_DEBUG_ERR, "unknown akm for config response: %s\n", cp->akm);
                }
                tlv = TLV_set_tlv(tlv, CONFIGURATION_OBJECT, sofar, (unsigned char *)confresp);
                dpp_debug(DPP_DEBUG_TRACE, "adding %d byte config object for %s to %s\n",
                          sofar, cp->akm, cp->ssid);
            }
            break;
        case STATUS_CONFIGURE_FAILURE:
            dpp_debug(DPP_DEBUG_ERR, "failed to generate configuration object!\n");
            break;
        case STATUS_CSR_NEEDED:
            if ((sofar = gen_csrattrs(confresp)) < 0) {
                dpp_debug(DPP_DEBUG_ERR, "failed to create CSR attrs!\n");
                status = STATUS_CONFIGURE_FAILURE;
            } else {
                tlv = TLV_set_tlv(tlv, CSR_ATTRS_REQUEST, sofar, (unsigned char *)confresp);
                dpp_debug(DPP_DEBUG_TRACE, "adding CSR attributes request to config response\n");
            }
            break;
        case STATUS_NEW_KEY_NEEDED:
            dpp_debug(DPP_DEBUG_TRACE, "asking enrollee to generate a new protocol key in %d!\n",
                      dpp_instance.newgroup);
            if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
                ((newpub = EC_KEY_get0_public_key(peer->mynewproto)) == NULL) ||
                !EC_POINT_get_affine_coordinates_GFp((EC_GROUP *)EC_KEY_get0_group(peer->mynewproto),
                                                     newpub, x, y, bnctx)) {
                dpp_debug(DPP_DEBUG_ERR, "failed to get new public key!\n");
                status = STATUS_CONFIGURE_FAILURE;
                break;
            }
            /*
             * add the new finite cyclic group and our new protocol key from it
             */
            grp = ieee_order(dpp_instance.newgroup);
            tlv = TLV_set_tlv(tlv, FINITE_CYCLIC_GROUP, sizeof(unsigned short), (unsigned char *)&grp);
            tlv->type = RESPONDER_PROTOCOL_KEY;
            tlv->length = 2 * peer->newprimelen;
            ptr = tlv->value;
            offset = peer->newprimelen - BN_num_bytes(x);
            BN_bn2bin(x, ptr + offset);
            ptr += peer->newprimelen;
            offset = peer->newprimelen - BN_num_bytes(y);
            BN_bn2bin(y, ptr + offset);
            tlv = TLV_next(tlv);
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "unknown status %d sent to gen_dpp_config_resp_frame()\n", status);
            break;
    }

    wraptlv->length = (int)((unsigned char *)tlv - (unsigned char *)wraptlv->value);
    wrapped_len = wraptlv->length - AES_BLOCK_SIZE;
    /*
     * ieee-ize the attributes that get encrypted
     */
    ieeeize_hton_attributes(encrypt_ptr, (int)(((unsigned char *)tlv - encrypt_ptr)));

    /*
     * in case something failed and the status got reset, set the status again
     */
    (void)TLV_set_tlv((TLV *)peer->buffer, DPP_STATUS, 1, &status);
    
    /*
     * ...and then ieee-ize the attributes that don't get encrypted
     */
    ieeeize_hton_attributes(peer->buffer, (int)(((unsigned char *)tlv - peer->buffer)));

    switch(dpp_instance.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_512);
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", dpp_instance.digestlen);
    }
    siv_encrypt(&ctx, wraptlv->value + AES_BLOCK_SIZE, encrypt_ptr, wrapped_len,
                wraptlv->value, 1, &peer->buffer,
                (int)((unsigned char *)wraptlv - (unsigned char *)peer->buffer));

    peer->bufferlen = (int)((unsigned char *)tlv - peer->buffer);

    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
    if (signprime != NULL) {
        BN_free(signprime);
    }
    if (bn != NULL) {
        free(bn);
    }
    return 1;
}

static int
send_dpp_config_req_frame (struct candidate *peer)
{
    siv_ctx ctx;
    TLV *tlv;
    int ret = -1, caolen = 0, offset;
    char confattsobj[1500], whoami[20], *csr = NULL;
    unsigned char *ptr, *xoctets = NULL;
    unsigned int mdlen = 0;
    HMAC_CTX *hctx = NULL;
    BIGNUM *x = NULL, *y = NULL, *Sx = NULL;
    const BIGNUM *pc;
    EC_POINT *S;
    unsigned char sx[SHA512_DIGEST_LENGTH], auth[SHA512_DIGEST_LENGTH], k[SHA512_DIGEST_LENGTH];
    
    memset(peer->buffer, 0, sizeof(peer->buffer));
    peer->nextfragment = 0;     // so enrollee can reuse the buffer when he's done sending
    peer->bufferlen = 0;
    peer->dialog_token = 1;

    if (gethostname(whoami, sizeof(whoami)) < 0) {
        dpp_debug(DPP_DEBUG_ERR, "unable to determine hostname!\n");
        strcpy(whoami, "dunno");
    }
    tlv = (TLV *)peer->buffer;
    tlv->type = ieee_order(WRAPPED_DATA);
    tlv = (TLV *)(tlv->value + AES_BLOCK_SIZE);

    tlv = TLV_set_tlv(tlv, ENROLLEE_NONCE, dpp_instance.noncelen, peer->enonce);
    /*
     * if we generated a new key pair then communicate that back
     */
    if (peer->mynewproto != NULL) {
        dpp_debug(DPP_DEBUG_TRACE, "adding new protocol key...\n");
        if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
            ((hctx = HMAC_CTX_new()) == NULL) ||
            !EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(peer->mynewproto),
                                                 EC_KEY_get0_public_key(peer->mynewproto),
                                                 x, y, bnctx)) {
            if (x != NULL) {
                BN_free(x);
            }
            if (y != NULL) {
                BN_free(y);
            }
            if (hctx != NULL) {
                HMAC_CTX_free(hctx);
            }
            return ret;
        }
        /*
         * x- and y-coordinates of new protocol key...
         */
        tlv->type = INITIATOR_PROTOCOL_KEY;
        tlv->length = 2 * peer->newprimelen;
        ptr = tlv->value;
        offset = peer->newprimelen - BN_num_bytes(x);
        BN_bn2bin(x, ptr + offset);
        ptr += peer->newprimelen;
        offset = peer->newprimelen - BN_num_bytes(y);
        BN_bn2bin(y, ptr + offset);
        BN_free(x);
        BN_free(y);

        if (((Sx = BN_new()) == NULL) ||
            (S = EC_POINT_new(EC_KEY_get0_group(peer->mynewproto))) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "cannot create POP secret!\n");
            HMAC_CTX_free(hctx);
            return ret;
        }
        if (((pc = EC_KEY_get0_private_key(peer->mynewproto)) == NULL) ||
            !EC_POINT_mul(EC_KEY_get0_group(peer->mynewproto), S, NULL, peer->peernewproto, pc, bnctx) ||
            !EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(peer->mynewproto),
                                                 S, Sx, NULL, bnctx)) {
            dpp_debug(DPP_DEBUG_ERR, "failure to compute shared key for POP!\n");
            BN_free(Sx);
            EC_POINT_free(S);
            HMAC_CTX_free(hctx);
            return ret;
        }
        memset(k, 0, SHA512_DIGEST_LENGTH);
        offset = peer->newprimelen - BN_num_bytes(Sx);
        BN_bn2bin(Sx, sx + offset);
        hkdf(dpp_instance.hashfcn, 0,
             sx, peer->newprimelen,
             peer->bk, dpp_instance.digestlen,
             (unsigned char *)"New DPP Protocol Key", strlen("New DPP Protocol Key"),
             k, dpp_instance.digestlen);

        /*
         * ...and an auth tag to prove possession
         */
        tlv = TLV_next(tlv);
        if (((xoctets = (unsigned char *)malloc(peer->newprimelen)) == NULL) ||
            ((x = BN_new()) == NULL)) {
            dpp_debug(DPP_DEBUG_ERR, "internal error trying to do POP!\n");
            BN_free(Sx);
            EC_POINT_free(S);
            HMAC_CTX_free(hctx);
            return ret;
        }
        HMAC_Init_ex(hctx, k, dpp_instance.digestlen, dpp_instance.hashfcn, NULL);
        /*
         * An HMAC keyed with k, and a body consisting of first the e-nonce...
         */
        HMAC_Update(hctx, peer->enonce, dpp_instance.noncelen);
        /*
         * then the x-coordinates of the two public keys...
         */
        if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(peer->mynewproto),
                                                 peer->peernewproto, x, NULL, bnctx)) {
            dpp_debug(DPP_DEBUG_ERR, "cannot get coordinates from peer's new protocol key!\n");
            free(xoctets);
            EC_POINT_free(S);
            BN_free(Sx);
            BN_free(x);
            HMAC_CTX_free(hctx);
            return ret;
        }
        memset(xoctets, 0, peer->newprimelen);
        offset = peer->newprimelen - BN_num_bytes(x);
        BN_bn2bin(x, xoctets + offset);
        HMAC_Update(hctx, xoctets, peer->newprimelen);
        
        if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(peer->mynewproto),
                                                 EC_KEY_get0_public_key(peer->mynewproto), x,
                                                 NULL, bnctx)) {
            dpp_debug(DPP_DEBUG_ERR, "cannot get coordinates from our new protocol key!\n");
            free(xoctets);
            EC_POINT_free(S);
            BN_free(Sx);
            BN_free(x);
            HMAC_CTX_free(hctx);
            return ret;
        }
        memset(xoctets, 0, peer->newprimelen);
        offset = peer->newprimelen - BN_num_bytes(x);
        BN_bn2bin(x, xoctets + offset);
        HMAC_Update(hctx, xoctets, peer->newprimelen);

        mdlen = dpp_instance.digestlen;
        HMAC_Final(hctx, auth, &mdlen);

        dpp_debug(DPP_DEBUG_TRACE, "adding POP auth tag...\n");
        tlv = TLV_set_tlv(tlv, INITIATOR_AUTH_TAG, mdlen, auth);
        free(xoctets);
        EC_POINT_free(S);
        BN_free(Sx);
        BN_free(x);
        HMAC_CTX_free(hctx);
    }
    
    /*
     * standard config object request, plus if we have a MUD URL then send it, if we have
     * csr attributes then generate a CSR too
     */
    caolen = snprintf(confattsobj, sizeof(confattsobj),
                      "{ \"name\":\"%s\", \"wi-fi_tech\":\"infra\", \"netRole\":\"%s\"",
                      whoami, dpp_instance.enrollee_role);
    if (dpp_instance.mudurl[0] != 0) {
        caolen += snprintf(confattsobj+caolen, sizeof(confattsobj)-caolen,
                          ",\"mudurl\":\"%s\"", dpp_instance.mudurl);
    }
    if (peer->csrattrs != NULL) {
        if (generate_csr(peer, &csr) < 1) {
            dpp_debug(DPP_DEBUG_ERR, "cannot generate CSR!\n");
            return -1;
        }
        caolen += snprintf(confattsobj+caolen, sizeof(confattsobj)-caolen,
                           ",\"pkcs10\":\"%s\"", csr);
        free(csr);
        free(peer->csrattrs);
        peer->csrattrs = NULL;
        peer->csrattrs_len = 0;
    }
    caolen += snprintf(confattsobj+caolen, sizeof(confattsobj)-caolen, "}");

    tlv = TLV_set_tlv(tlv, CONFIG_ATTRIBUTES_OBJECT, caolen, (unsigned char *)confattsobj);
    /*
     * put the attributes into ieee-order
     */
    ieeeize_hton_attributes((((TLV *)peer->buffer)->value + AES_BLOCK_SIZE),
                            (int)((unsigned char *)tlv - (((TLV *)peer->buffer)->value + AES_BLOCK_SIZE)));
    
    switch(dpp_instance.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_512);
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", dpp_instance.digestlen);
    }
    /*
     * fill in the lengths now that we have constructed the frame...
     */
    peer->bufferlen = (int)((unsigned char *)tlv - peer->buffer);

    tlv = (TLV *)peer->buffer;
    /*
     * only 1 attribute to put into ieee-order...
     */
    tlv->length = ieee_order(peer->bufferlen - sizeof(TLV));

    siv_encrypt(&ctx, tlv->value + AES_BLOCK_SIZE, tlv->value + AES_BLOCK_SIZE,
                (peer->bufferlen - sizeof(TLV)) - AES_BLOCK_SIZE,
                tlv->value, 0);

    if (send_dpp_config_frame(peer, GAS_INITIAL_REQUEST)) {
        peer->retrans = 0;
        peer->t0 = srv_add_timeout(srvctx, SRV_SEC(5), retransmit_config, peer);
    }
    ret = 1;

    return ret;
}

/*
 * Got a COMEBACK_RESPONSE telling us to comeback later, that time is NOW!
 */
static void
cameback_delayed (timerid id, void *data)
{
    struct candidate *peer = (struct candidate *)data;

    send_dpp_config_frame(peer, GAS_COMEBACK_REQUEST);
    peer->t0 = srv_add_timeout(srvctx, SRV_SEC(5), retransmit_config, peer);
}

static int
process_dpp_config_result (struct candidate *peer, unsigned char *data, int len)
{
    dpp_action_frame *frame = (dpp_action_frame *)data;
    TLV *tlv;
    siv_ctx ctx;
    unsigned char *status;
    int res = -1;

    dpp_debug(DPP_DEBUG_TRACE, "processing dpp config result\n");
    ieeeize_ntoh_attributes(frame->attributes, len - sizeof(dpp_action_frame));
    tlv = (TLV *)frame->attributes;
    if (TLV_type(tlv) != WRAPPED_DATA) {
        dpp_debug(DPP_DEBUG_ERR, "missing wrapped data in DPP Config result!\n");
        goto fin;
    }
    /*
     * decrypt the wrapped data
     */
    switch(dpp_instance.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_512);
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", dpp_instance.digestlen);
            goto fin;
    }
    
    if (siv_decrypt(&ctx, TLV_value(tlv) + AES_BLOCK_SIZE, TLV_value(tlv) + AES_BLOCK_SIZE,
                    TLV_length(tlv) - AES_BLOCK_SIZE, TLV_value(tlv),
                    2, data, sizeof(dpp_action_frame), frame->attributes, 0) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "can't decrypt DPP Config result!\n");
        goto fin;
    }
    tlv = (TLV *)(TLV_value(tlv) + AES_BLOCK_SIZE);
    if ((TLV_type(tlv) != DPP_STATUS) || (TLV_length(tlv) != 1)) {
        dpp_debug(DPP_DEBUG_ERR, "missing status in DPP config result!\n");
        goto fin;
    }
    status = TLV_value(tlv);
    if (*status != STATUS_OK) {
        dpp_debug(DPP_DEBUG_ANY, "bad status %d from peer\n", *status);
        goto fin;
    }
    tlv = TLV_next(tlv);
    if (memcmp(TLV_value(tlv), peer->enonce, dpp_instance.noncelen)) {
        dpp_debug(DPP_DEBUG_ANY, "incorrect enonce in DPP config result!\n");
        goto fin;
    }
    dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "peer has successfully been provisioned!\n");
    res = 1;
fin:
    return res;
}

static int
check_connector (struct candidate *peer, unsigned char *blob, int len)
{
    unsigned char unb64url[1024], coordbin[P521_COORD_LEN];
    BIGNUM *x = NULL, *y = NULL;
    const EC_POINT *P;
    const EC_GROUP *signgroup;
    char *sstr, *estr, *dot;
    int ntok, unburllen, cl, signnid, coordlen, ret = -1;

    if ((ntok = get_json_data((char *)blob, len, &sstr, &estr, 2, "cred", "signedConnector")) == 0) {
        dpp_debug(DPP_DEBUG_ERR, "No connector found!\n");
        goto fin;
    }
    dot = strstr(sstr, ".");
    memset(unb64url, 0, sizeof(unb64url));
    /*
     * decode the JWS Protected Header
     */
    if ((unburllen = base64urldecode(unb64url, (unsigned char *)sstr, dot-sstr)) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "Cannot base64url decode the JWS Protected Header!\n");
        goto fin;
    }
    if ((ntok = get_json_data((char *)unb64url, unburllen, &sstr, &estr, 1, "alg")) != 1) {
        dpp_debug(DPP_DEBUG_ERR, "Failed to get 'alg' from JWS Protected Header!\n");
        goto fin;
    }
    dpp_debug(DPP_DEBUG_TRACE, "connector is signed with %.*s, ", (int)(estr - sstr), sstr);
    if ((ntok = get_json_data((char *)unb64url, unburllen, &sstr, &estr, 1, "kid")) != 1) {
        dpp_debug(DPP_DEBUG_ERR, "Failed to get 'kid' from JWS Protected Header!\n");
        goto fin;
    }
    dpp_debug(DPP_DEBUG_TRACE, "by key with key id:\n %.*s\n", (int)(estr - sstr), sstr);
    /*
     * get the Configurator's signing key from the "csign" portion of the DPP Config Object
     */
    if ((ntok = get_json_data((char *)blob, len, &sstr, &estr, 3, "cred", "csign", "crv")) != 1) {
        dpp_debug(DPP_DEBUG_ERR, "No 'crv' coordinate in 'csign' portion of the response!\n");
        goto fin;
    }
    if ((int)(estr - sstr) > 6) {
        dpp_debug(DPP_DEBUG_ERR, "malformed 'crv' in 'csign' portion of response (%d chars)\n",
                  (int)(estr - sstr));
        goto fin;
    }
    
    if (strncmp(sstr, "P-256", 5) == 0) {
        signnid = NID_X9_62_prime256v1;
        coordlen = P256_COORD_LEN;
    } else if (strncmp(sstr, "P-384", 5) == 0) {
        signnid = NID_secp384r1;
        coordlen = P384_COORD_LEN;
    } else if (strncmp(sstr, "P-521", 5) == 0) {
        signnid = NID_secp521r1;
        coordlen = P521_COORD_LEN;
#ifdef HAS_BRAINPOOL
    } else if (strncmp(sstr, "BP-256", 6) == 0) {
        signnid = NID_brainpoolP256r1;
        coordlen = P256_COORD_LEN;
    } else if (strncmp(sstr, "BP-384", 6) == 0) {
        signnid = NID_brainpoolP384r1;
        coordlen = P384_COORD_LEN;
    } else if (strncmp(sstr, "BP-512", 6) == 0) {
        signnid = NID_brainpoolP512r1;
        coordlen = P512_COORD_LEN;
#endif  /* HAS_BRAINPOOL */
    } else {
        dpp_debug(DPP_DEBUG_ERR, "unknown elliptic curve %.*s!\n", (int)(estr - sstr), sstr);
        goto fin;
    }

    if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to get coordinates to create configurator's signing key\n");
        goto fin;
    }
    /*
     * get the x-coordinate...
     */
    if ((ntok = get_json_data((char *)blob, len, &sstr, &estr, 3, "cred", "csign", "x")) != 1) {
        dpp_debug(DPP_DEBUG_ERR, "No 'x' coordinate in 'csign' portion of the response!\n");
        goto fin;
    }
    
    if ((int)(estr - sstr) > (((coordlen+2)/3) * 4)) {
        dpp_debug(DPP_DEBUG_ERR, "Mal-sized x-coordinate (%d)\n",
                  (int)(estr - sstr));
        goto fin;
    }
    memset(coordbin, 0, coordlen);
    if ((cl = base64urldecode(coordbin, (unsigned char *)sstr, ((int)(estr - sstr)))) != coordlen) {
        dpp_debug(DPP_DEBUG_ERR, "b64url-decoded wrong-sized coordinate: %d instead of %d\n", cl, coordlen);
        print_buffer("coord-x", coordbin, cl);
        goto fin;
    }
    BN_bin2bn(coordbin, coordlen, x);
    /*
     * get the y-coordinate...
     */
    if ((ntok = get_json_data((char *)blob, len, &sstr, &estr, 3, "cred", "csign", "y")) != 1) {
        dpp_debug(DPP_DEBUG_ERR, "No 'y' coordinate in 'csign' portion of the response!\n");
        goto fin;
    }
    if ((int)(estr - sstr) > (((coordlen+2)/3) * 4)) {
        dpp_debug(DPP_DEBUG_ERR, "Mal-sized y-coordinate (%d)\n",
                  (int)(estr - sstr));
        goto fin;
    }
    memset(coordbin, 0, coordlen);
    if (base64urldecode(coordbin, (unsigned char *)sstr, ((int)(estr - sstr))) != coordlen) {
        dpp_debug(DPP_DEBUG_ERR, "b64url-decoded wrong-sized coordinate\n");
        goto fin;
    }
    BN_bin2bn(coordbin, coordlen, y);

    /*
     * create an EC_KEY out of "crv", "x", and "y"
     */
    configurator_signkey = EC_KEY_new_by_curve_name(signnid);
    EC_KEY_set_public_key_affine_coordinates(configurator_signkey, x, y);
    EC_KEY_set_conv_form(configurator_signkey, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(configurator_signkey, OPENSSL_EC_NAMED_CURVE);
    if (((signgroup = EC_KEY_get0_group(configurator_signkey)) == NULL) ||
        ((P = EC_KEY_get0_public_key(configurator_signkey)) == NULL) ||
        !EC_POINT_is_on_curve(signgroup, P, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "configurator's signing key is not valid!\n");
        goto fin;
    }
    dpp_debug(DPP_DEBUG_TRACE, "configurator's signing key is valid!!!\n");

    if (get_kid_from_point(csign_kid, signgroup, P, bnctx) < KID_LENGTH) {
        dpp_debug(DPP_DEBUG_ERR, "can't get key id for configurator's sign key!\n");
        goto fin;
    }
        
    /*
     * validate the connector
     */
    if ((ntok = get_json_data((char *)blob, len, &sstr, &estr, 2, "cred", "signedConnector")) == 0) {
        dpp_debug(DPP_DEBUG_ERR, "No connector in DPP Config response!\n");
        goto fin;
    }
    if (validate_connector((unsigned char *)sstr, (int)(estr - sstr), configurator_signkey, bnctx) < 0) {
        dpp_debug(DPP_DEBUG_ERR, "signature on connector is bad!\n");
        goto fin;
    }
    connector_len = (int)(estr - sstr);
    if ((connector = malloc(connector_len)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to allocate a connector!\n");
        goto fin;
    }
    memcpy(connector, sstr, connector_len);
    ret = 1;
fin:
    if (ret < 1) {
        if (configurator_signkey != NULL) {
            EC_KEY_free(configurator_signkey);
        }
    }
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
    return ret;
}

static int
process_dpp_config_response (struct candidate *peer, unsigned char *attrs, int len)
{
    TLV *tlv;
    unsigned char *val;
    EVP_ENCODE_CTX *ectx = NULL;
    BIGNUM *x = NULL, *y = NULL;
    siv_ctx ctx;
    char *sstr, *estr;
    unsigned short newgrp;
    int i, wrapdatalen, ntok, ncred, ret = -1;

    dpp_debug(DPP_DEBUG_TRACE, "got a DPP config response!\n");

    ieeeize_ntoh_attributes(attrs, len);
    tlv = (TLV *)attrs;
    if ((TLV_type(tlv) != DPP_STATUS) || (TLV_length(tlv) != 1)) {
        dpp_debug(DPP_DEBUG_ERR, "missing status in DPP Config Response!\n");
        goto fin;
    }
    val = TLV_value(tlv);
    tlv = TLV_next(tlv);
    if (TLV_type(tlv) != WRAPPED_DATA) {
        dpp_debug(DPP_DEBUG_ERR, "missing wrapped data in DPP Config Response!\n");
        goto fin;
    }
    /*
     * decrypt the wrapped data
     */
    switch(dpp_instance.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_512);
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", dpp_instance.digestlen);
            goto fin;
    }
    wrapdatalen = TLV_length(tlv) - AES_BLOCK_SIZE;
    if (siv_decrypt(&ctx, TLV_value(tlv) + AES_BLOCK_SIZE, TLV_value(tlv) + AES_BLOCK_SIZE,
                    wrapdatalen, TLV_value(tlv), 1, attrs,
                    (int)((unsigned char *)tlv - attrs)) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "can't decrypt DPP Config response!\n");
        goto fin;
    }
    tlv = (TLV *)(TLV_value(tlv) + AES_BLOCK_SIZE);
    if (TLV_type(tlv) != ENROLLEE_NONCE) {
        dpp_debug(DPP_DEBUG_ERR, "no enrollee nonce in DPP Config response!\n");
        goto fin;
    }
    if (memcmp(TLV_value(tlv), peer->enonce, dpp_instance.noncelen)) {
        dpp_debug(DPP_DEBUG_ERR, "configurator did not return the right nonce!!!\n");
        goto fin;
    }
    /*
     * keep track of how much wrapped data we have left
     */
    wrapdatalen -= TLV_length(tlv);
    /*
     * next!
     */
    tlv = TLV_next(tlv);

    switch (*val) {
        case STATUS_OK:
            /*
             * Everything's good, so there will be connectors in this goo somewhere,
             * ensure the right protocol key is ready when we go writing config files...
             */
            if ((peer->version > 1) && (peer->mynewproto != NULL)) {
                if ((netaccesskey = EC_KEY_dup(peer->mynewproto)) == NULL) {
                    dpp_debug(DPP_DEBUG_ERR, "Unable to copy protocol key for network access!\n");
                    goto fin;
                }
            } else {
                if ((netaccesskey = EC_KEY_dup(peer->my_proto)) == NULL) {
                    dpp_debug(DPP_DEBUG_ERR, "Unable to copy protocol key for network access!\n");
                    goto fin;
                }
            }
            /*
             * there should be one or more configuration objects, go through them all...
             */
            TLV_foreach(tlv, i, wrapdatalen) {
                if (TLV_type(tlv) != CONFIGURATION_OBJECT) {
                    dpp_debug(DPP_DEBUG_ERR, "Other than Configuration Object in the DPP Config response: %s!\n",
                              TLV_type_string(tlv));
                    /*
                     * be liberal in what we accept...
                     */
                    continue;
                }
                dpp_debug(DPP_DEBUG_TRACE, "\ncredential object:\n");
                dpp_debug(DPP_DEBUG_TRACE, "%.*s\n\n", TLV_length(tlv), TLV_value(tlv));
                if ((ncred = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                           &sstr, &estr, 2, "cred", "akm")) == 0) {
                    dpp_debug(DPP_DEBUG_ERR, "No AKM credential in DPP Config response!\n");
                    goto fin;
                }
                if (ncred < 1) {
                    dpp_debug(DPP_DEBUG_ERR, "Got back %d credentials... bailing!\n", ncred);
                    goto fin;
                }
                if (strncmp(sstr, "dpp", 3) == 0) {
                    /*
                     * we got a connector!
                     */
                    dpp_debug(DPP_DEBUG_TRACE, "A DPP AKM Configuration Object!\n");
                    if (check_connector(peer, TLV_value(tlv), TLV_length(tlv)) < 0) {
                        dpp_debug(DPP_DEBUG_ERR, "Bad connector in DPP AKM of Config response!\n");
                        goto fin;
                    }
                    if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                              &sstr, &estr, 2, "discovery", "ssid")) == 0) {
                        provision_connector(dpp_instance.enrollee_role, "*", 1,
                                            connector, connector_len, peer->handle);
                        dump_key_con(peer, NULL, 0);
                    } else {
                        provision_connector(dpp_instance.enrollee_role, sstr, (int)(estr - sstr),
                                            connector, connector_len, peer->handle);
                        dump_key_con(peer, sstr, (int)(estr - sstr));
                    }
                } else if (strncmp(sstr, "sae", 3) == 0) {
                    char pwd[80];

                    dpp_debug(DPP_DEBUG_TRACE, "An SAE AKM Configuration Object!\n");
                    memset(pwd, 0, 80);
                    /*
                     * got a PSK configuration!
                     */
                    if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                              &sstr, &estr, 2, "cred", "pass")) != 0) {
                        dpp_debug(DPP_DEBUG_TRACE, "use password '%.*s' ", (int)(estr - sstr), sstr);
                        strncpy(pwd, sstr, (int)(estr - sstr));
                    } else {
                        dpp_debug(DPP_DEBUG_ERR, "Unknown type of sae, not 'pass'\n");
                        goto fin;
                    }
                    if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                              &sstr, &estr, 2, "discovery", "ssid")) == 0) {
                        dpp_debug(DPP_DEBUG_TRACE, "with an any SSID I guess\n");
                    } else {
                        dpp_debug(DPP_DEBUG_TRACE, "with SSID %.*s\n", (int)(estr - sstr), sstr);
                    }
                    if (peer->version > 1) {
                        /*
                         * connector is v2 only
                         */
                        if (check_connector(peer, TLV_value(tlv), TLV_length(tlv)) < 0) {
                            dpp_debug(DPP_DEBUG_ERR, "Bad connector in SAE AKM of Config response!\n");
                            goto fin;
                        }
                        provision_connector(dpp_instance.enrollee_role, sstr, (int)(estr - sstr),
                                            connector, connector_len, peer->handle);
                        dump_key_con(peer, NULL, 0);
                        dpp_debug(DPP_DEBUG_TRACE, "got valid connector with SAE config\n");
                    }
                    dump_pwd_con(sstr, (int)(estr - sstr), pwd, 1);
                } else if (strncmp(sstr, "psk", 3) == 0) {
                    char pwd[80];

                    dpp_debug(DPP_DEBUG_TRACE, "An PSK AKM Configuration Object!\n");
                    memset(pwd, 0, 80);
                    /*
                     * got a PSK configuration!
                     */
                    if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                              &sstr, &estr, 2, "cred", "pass")) != 0) {
                        dpp_debug(DPP_DEBUG_TRACE, "use passphrase '%.*s' ", (int)(estr - sstr), sstr);
                        strncpy(pwd, sstr, (int)(estr - sstr));
                    } else if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                                     &sstr, &estr, 2, "cred", "psk_hex")) != 0) {
                        dpp_debug(DPP_DEBUG_TRACE, "use hexstring '%.*s' ", (int)(estr - sstr), sstr);
                        strncpy(pwd, sstr, (int)(estr - sstr));
                    } else {
                        dpp_debug(DPP_DEBUG_ERR, "Unknown type of psk, not 'pass' and not 'psk_hex'\n");
                        goto fin;
                    }
                    if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                              &sstr, &estr, 2, "discovery", "ssid")) == 0) {
                        dpp_debug(DPP_DEBUG_TRACE, "with an any SSID I guess\n");
                    } else {
                        dpp_debug(DPP_DEBUG_TRACE, "with SSID %.*s\n", (int)(estr - sstr), sstr);
                    }
                    if (peer->version > 1) {
                        /*
                         * connector is v2 only
                         */
                        if (check_connector(peer, TLV_value(tlv), TLV_length(tlv)) < 0) {
                            dpp_debug(DPP_DEBUG_ERR, "Bad connector in PSK AKM of Config response!\n");
                            goto fin;
                        }
                        provision_connector(dpp_instance.enrollee_role, sstr, (int)(estr - sstr),
                                            connector, connector_len, peer->handle);
                        dump_key_con(peer, NULL, 0);
                        dpp_debug(DPP_DEBUG_TRACE, "got valid connector with PSK config\n");
                    }
                    dump_pwd_con(sstr, (int)(estr - sstr), pwd, 0);
                } else if (strncmp(sstr, "dot1x", 4) == 0) {
                    char *p7, *ca, *san;
                    int p7len, calen, sanlen;
            
                    if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                              &sstr, &estr, 3, "cred", "entCreds", "certBag")) < 1) {
                        dpp_debug(DPP_DEBUG_ERR, "No certBag in DPP Config response for dot1x!\n");
                        goto fin;
                    }
                    dpp_debug(DPP_DEBUG_PKI, "got PKCS#7:\n %.*s\n", (int)(estr - sstr), sstr);
                    p7 = sstr;
                    p7len = (int)(estr - sstr);
                    if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                              &sstr, &estr, 3, "cred", "entCreds", "caCert")) < 1) {
                        dpp_debug(DPP_DEBUG_ERR, "No caCert in DPP Config response for dot1x!\n");
                        ca = NULL;
                        calen = 0;
                    } else {
                        ca = sstr;
                        calen = (int)(estr - sstr);
                        dpp_debug(DPP_DEBUG_PKI, "got CA cert:\n %.*s\n", calen, ca);
                    }
                    if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                              &sstr, &estr, 3, "cred", "entCreds", "trustedEapServerName")) < 1) {
                        dpp_debug(DPP_DEBUG_ERR, "No SAN to match in server cert!\n");
                        san = NULL;
                        sanlen = 0;
                    } else {
                        dpp_debug(DPP_DEBUG_ERR, "Got a SAN to match in server cert!\n");
                        san = sstr;
                        sanlen = (int)(estr - sstr);
                    }
                    extract_certs(p7, p7len, ca, calen);
                    if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                              &sstr, &estr, 2, "discovery", "ssid")) == 0) {
                        dpp_debug(DPP_DEBUG_TRACE, "with an any SSID I guess\n");
                    } else {
                        dpp_debug(DPP_DEBUG_TRACE, "with SSID %.*s\n", (int)(estr - sstr), sstr);
                    }
                    dump_cert_con(sstr, (int)(estr - sstr), p7, p7len, san, sanlen);
                    /*
                     * dot1x credentials are v2 only so there'll always be a connector
                     */
                    if (check_connector(peer, TLV_value(tlv), TLV_length(tlv)) < 0) {
                        dpp_debug(DPP_DEBUG_ERR, "Bad connector in dot1x AKM of Config response!\n");
                        goto fin;
                    }
                    provision_connector(dpp_instance.enrollee_role, sstr, (int)(estr - sstr),
                                        connector, connector_len, peer->handle);
                    dump_key_con(peer, NULL, 0);
                    dpp_debug(DPP_DEBUG_TRACE, "got valid connector with dot1x config\n");
                } else {
                    dpp_debug(DPP_DEBUG_ERR, "Unknown credential type %.*s!\n", (int)(estr - sstr), sstr);
                    goto fin;
                }
            }
            ret = 1;
            break;
        case STATUS_CONFIGURE_PENDING:
            dpp_debug(DPP_DEBUG_TRACE, "Configurator said configuration is pending...\n");
            ret = -1;           // don't support this yet
            break;
        case STATUS_CSR_NEEDED:
            if (TLV_type(tlv) != CSR_ATTRS_REQUEST) {
                dpp_debug(DPP_DEBUG_ERR, "status says CSR needed but no CSR Attrs request!\n");
                goto fin;
            }
            dpp_debug(DPP_DEBUG_TRACE, "Configurator said we need a CSR to continue...\n");
            /*
             * OK, gotta start over and supply a CSR...
             */
            debug_buffer(DPP_DEBUG_TRACE, "CSR Attributes", TLV_value(tlv), TLV_length(tlv));
            if ((peer->csrattrs = (char *)malloc(2*TLV_length(tlv))) == NULL) {
                goto fin;
            }
            if ((ectx = EVP_ENCODE_CTX_new()) == NULL) {
                goto fin;
            }
            /*
             * base64 decode the CSR Attrs to get an ASN.1 SEQUENCE OF...
             */
            EVP_DecodeInit(ectx);
            (void)EVP_DecodeUpdate(ectx, (unsigned char *)peer->csrattrs, &i, TLV_value(tlv), TLV_length(tlv));
            peer->csrattrs_len = i;
            (void)EVP_DecodeFinal(ectx, (unsigned char *)&(peer->csrattrs[i]), &i);
            peer->csrattrs_len += i;
            send_dpp_config_req_frame(peer);
            ret = 0;
            break;
        case STATUS_NEW_KEY_NEEDED:
            if ((TLV_type(tlv) != FINITE_CYCLIC_GROUP) ||
                (TLV_lookahead(tlv) != RESPONDER_PROTOCOL_KEY)) {
                dpp_debug(DPP_DEBUG_ERR, "status says new key needed but no group/key in response\n");
                goto fin;
            }
            /*
             * extract the peer's protocol key, generate one and grab peer's new one...
             */
            memcpy((unsigned short *)&newgrp, TLV_value(tlv), sizeof(unsigned short));
            newgrp = ieee_order(newgrp);
            dpp_debug(DPP_DEBUG_TRACE, "Configurator said we need to generate a new key in %d to continue...\n",
                      newgrp);
            if ((peer->mynewproto = generate_new_protocol_key(newgrp)) == NULL) {
                dpp_debug(DPP_DEBUG_ERR, "can't generate new protocol key in group %d\n", newgrp);
                goto fin;
            }
            peer->newprimelen = prime_len_by_curve(newgrp);
            tlv = TLV_next(tlv);
            if (((peer->peernewproto = EC_POINT_new(EC_KEY_get0_group(peer->mynewproto))) == NULL) ||
                ((x = BN_new()) == NULL) || ((y = BN_new()) == NULL)) {
                dpp_debug(DPP_DEBUG_ERR, "can't generate peer's new protocol key!\n");
                goto fin;
            }
            BN_bin2bn(TLV_value(tlv), peer->newprimelen, x);
            BN_bin2bn(TLV_value(tlv) + peer->newprimelen, peer->newprimelen, y);
            if (!EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(peer->mynewproto),
                                                     peer->peernewproto, x, y, bnctx) ||
                !EC_POINT_is_on_curve(EC_KEY_get0_group(peer->mynewproto), peer->peernewproto, bnctx)) {
                dpp_debug(DPP_DEBUG_ERR, "unable to assign peer's new protocol key!\n");
                goto fin;
            }
            send_dpp_config_req_frame(peer);
            ret = 0;
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "Configurator returned %d as status in DPP Config Response: FAIL!\n",
                      *val);
            break;
    }
fin:
    if (ectx != NULL) {
        EVP_ENCODE_CTX_free(ectx);
    }
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
    return ret;
}

static void
p7fromca (int s, void *data)
{
    struct candidate *peer = (struct candidate *)data;

    peer->p7 = NULL;
    if ((peer->p7len = get_pkcs7(s, &peer->p7)) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "cannot obtain p7 from CA!\n");
        generate_dpp_config_resp_frame(peer, STATUS_CONFIGURE_FAILURE);
    } else {
        dpp_debug(DPP_DEBUG_PKI, "got a %d byte PKCS7 from CA!\n", peer->p7len);
        generate_dpp_config_resp_frame(peer, STATUS_OK);
    }
    /*
     * generate a config response frame in the peer buffer and wait for
     * the next COMEBACK_REQUEST...
     */
    peer->state = DPP_PROVISIONING;     // put back into PROVISIONING state
    peer->nextfragment = 0;             // we start fragmenting at the beginning

    return;
}

static void
p10toca (struct candidate *peer, char *p10, int p10len)
{
    if (send_pkcs10(p10, p10len, dpp_instance.caip, peer, p7fromca) < 0) {
        dpp_debug(DPP_DEBUG_ERR, "unable to send PKCS10 to CA!\n");
        return;
    }
    dpp_debug(DPP_DEBUG_PKI, "send %d byte PKCS10 to CA!\n", p10len);
    return;
}

static int
process_dpp_config_request (struct candidate *peer, unsigned char *attrs, int len)
{
    TLV *tlv;
    int ntok;
    siv_ctx ctx;
    char *sstr, *estr;
    BIGNUM *x = NULL, *y = NULL, *Sx = NULL;
    const BIGNUM *pc;
    HMAC_CTX *hctx = NULL;
    EC_POINT *S;
    int offset;
    unsigned char sx[SHA512_DIGEST_LENGTH], auth[SHA512_DIGEST_LENGTH], k[SHA512_DIGEST_LENGTH];

    dpp_debug(DPP_DEBUG_TRACE, "got a DPP config request!\n");

    ieeeize_ntoh_attributes(attrs, len);
    tlv = (TLV *)attrs;
    if (TLV_type(tlv) != WRAPPED_DATA) {
        dpp_debug(DPP_DEBUG_ERR, "Wrapped data not in DPP Config Request!\n");
        return -1;
    }

    switch(dpp_instance.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_512);
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", dpp_instance.digestlen);
    }
    if (siv_decrypt(&ctx, tlv->value + AES_BLOCK_SIZE, tlv->value + AES_BLOCK_SIZE,
                    TLV_length(tlv) - AES_BLOCK_SIZE, TLV_value(tlv), 0) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "can't decrypt DPP Config Request frame!\n");
        return -1;
    }
    /*
     * ieee-ize the attribute lengths and point to the first TLV in the wrapped data
     */
    ieeeize_ntoh_attributes(TLV_value(tlv) + AES_BLOCK_SIZE, TLV_length(tlv) - AES_BLOCK_SIZE);
    tlv = (TLV *)(TLV_value(tlv) + AES_BLOCK_SIZE);

    if (TLV_type(tlv) != ENROLLEE_NONCE) {
        dpp_debug(DPP_DEBUG_ERR, "malformed wrapped data in DPP Config Request-- no E-nonce!\n");
        return -1;
    }
    memcpy(peer->enonce, TLV_value(tlv), TLV_length(tlv));
    
    tlv = TLV_next(tlv);
    /*
     * if we're asking for protocol keys then make sure those are in this request
     */
    if (dpp_instance.newgroup) {
        unsigned char *xoctets = NULL;
        unsigned int mdlen = 0;
        
        if ((TLV_type(tlv) != INITIATOR_PROTOCOL_KEY) ||
            (TLV_lookahead(tlv) != INITIATOR_AUTH_TAG)) {
            dpp_debug(DPP_DEBUG_TRACE, "we need a new protocol key but the enrollee didn't provide one\n");
            /*
             * we're the configurator, reuse the Pc key for all enrollees
             */
            peer->mynewproto = EC_KEY_dup(dpp_instance.Pc);
            peer->newprimelen = prime_len_by_curve(dpp_instance.newgroup);
            return 3;
        }
        dpp_debug(DPP_DEBUG_TRACE, "enrollee sent new protocol key and POP auth tag!\n");
        if (((peer->peernewproto = EC_POINT_new(EC_KEY_get0_group(peer->mynewproto))) == NULL) ||
            ((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
            ((hctx = HMAC_CTX_new()) == NULL)) {
            dpp_debug(DPP_DEBUG_ERR, "internal POP error (0)!\n");
            if (x != NULL) {
                BN_free(x);
            }
            if (y != NULL) {
                BN_free(y);
            }
            if (hctx != NULL) {
                HMAC_CTX_free(hctx);
            }
            return -1;
        }
        /*
         * extract and validate key
         */
        BN_bin2bn(TLV_value(tlv), peer->newprimelen, x);
        BN_bin2bn(TLV_value(tlv) + peer->newprimelen, peer->newprimelen, y);
        if (!EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(peer->mynewproto),
                                                 peer->peernewproto, x, y, bnctx) ||
            !EC_POINT_is_on_curve(EC_KEY_get0_group(peer->mynewproto), peer->peernewproto, bnctx)) {
            dpp_debug(DPP_DEBUG_ERR, "unable to create peer's new protocol key!\n");
            BN_free(x);
            BN_free(y);
            HMAC_CTX_free(hctx);
            return -1;
        }

        /*
         * compute S = pc * Pe and generate secret key k
         */
        if (((Sx = BN_new()) == NULL) ||
            (S = EC_POINT_new(EC_KEY_get0_group(peer->mynewproto))) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "internal POP error (1)!\n");
            BN_free(x);
            BN_free(y);
            HMAC_CTX_free(hctx);
            return -1;
        }
        if (((pc = EC_KEY_get0_private_key(peer->mynewproto)) == NULL) ||
            !EC_POINT_mul(EC_KEY_get0_group(peer->mynewproto), S, NULL, peer->peernewproto, pc, bnctx) ||
            !EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(peer->mynewproto),
                                                 S, Sx, NULL, bnctx)) {
            dpp_debug(DPP_DEBUG_ERR, "failure to compute shared key for POP!\n");
            BN_free(Sx);
            EC_POINT_free(S);
            BN_free(Sx);
            BN_free(x);
            BN_free(y);
            HMAC_CTX_free(hctx);
            return -1;
        }
        memset(k, 0, SHA512_DIGEST_LENGTH);
        memset(sx, 0, SHA512_DIGEST_LENGTH);
        offset = peer->newprimelen - BN_num_bytes(Sx);
        BN_bn2bin(Sx, sx + offset);
        hkdf(dpp_instance.hashfcn, 0,
             sx, peer->newprimelen,
             peer->bk, dpp_instance.digestlen,
             (unsigned char *)"New DPP Protocol Key", strlen("New DPP Protocol Key"),
             k, dpp_instance.digestlen);

        /*
         * make sure the authenticating tag is correct
         */
        tlv = TLV_next(tlv);
        if ((xoctets = (unsigned char *)malloc(peer->newprimelen)) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "internal POP error (2)!\n");
            EC_POINT_free(S);
            BN_free(Sx);
            BN_free(x);
            BN_free(y);
            HMAC_CTX_free(hctx);
            return -1;
        }
        HMAC_Init_ex(hctx, k, dpp_instance.digestlen, dpp_instance.hashfcn, NULL);
        /*
         * first the e-nonce...
         */
        HMAC_Update(hctx, peer->enonce, dpp_instance.noncelen);
        /*
         * then the x-coordinates of the two public keys...
         */
        if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(peer->mynewproto),
                                                 EC_KEY_get0_public_key(peer->mynewproto), x,
                                                 NULL, bnctx)) {
            dpp_debug(DPP_DEBUG_ERR, "cannot get coordinates from our new protocol key!\n");
            free(xoctets);
            EC_POINT_free(S);
            BN_free(Sx);
            BN_free(x);
            BN_free(y);
            HMAC_CTX_free(hctx);
            return -1;
        }
        memset(xoctets, 0, peer->newprimelen);
        offset = peer->newprimelen - BN_num_bytes(x);
        BN_bn2bin(x, xoctets + offset);
        HMAC_Update(hctx, xoctets, peer->newprimelen);
        
        if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(peer->mynewproto),
                                                 peer->peernewproto, x, NULL, bnctx)) {
            dpp_debug(DPP_DEBUG_ERR, "cannot get coordinates from peer's new protocol key!\n");
            free(xoctets);
            EC_POINT_free(S);
            BN_free(Sx);
            BN_free(x);
            BN_free(y);
            HMAC_CTX_free(hctx);
            return -1;
        }
        memset(xoctets, 0, peer->newprimelen);
        offset = peer->newprimelen - BN_num_bytes(x);
        BN_bn2bin(x, xoctets + offset);
        HMAC_Update(hctx, xoctets, peer->newprimelen);

        mdlen = dpp_instance.digestlen;
        HMAC_Final(hctx, auth, &mdlen);

        if (memcmp(auth, TLV_value(tlv), mdlen)) {
            dpp_debug(DPP_DEBUG_ERR, "POP failed for new protocol key!\n");
            free(xoctets);
            EC_POINT_free(S);
            BN_free(Sx);
            BN_free(x);
            BN_free(y);
            HMAC_CTX_free(hctx);
            return -1;
        }
        dpp_debug(DPP_DEBUG_TRACE, "POP passed for new protocol key\n");

        free(xoctets);
        EC_POINT_free(S);
        BN_free(Sx);
        BN_free(x);
        BN_free(y);
        HMAC_CTX_free(hctx);
        tlv = TLV_next(tlv);
    }
    if (TLV_type(tlv) != CONFIG_ATTRIBUTES_OBJECT) {
        dpp_debug(DPP_DEBUG_ERR, "malformed wrapped data in DPP Config Request-- no C-attrs!\n");
        return -1;
    }
    dpp_debug(DPP_DEBUG_ANY, "the json looks like %.*s\n",
              TLV_length(tlv), TLV_value(tlv));
    /*
     * parse the config attributes object for some interesting info
     */
    if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                              &sstr, &estr, 1, "name")) < 1) {
        return -1;
    }
    dpp_debug(DPP_DEBUG_ANY, "there are %d result(s) for 'name': %.*s\n",
              ntok, estr - sstr, sstr);
    if ((estr - sstr) > sizeof(peer->enrollee_name)) {
        strncpy(peer->enrollee_name, sstr, sizeof(peer->enrollee_name)-1);
    } else {
        strncpy(peer->enrollee_name, sstr, estr - sstr);
    }

    if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                              &sstr, &estr, 1, "netRole")) < 1) {
        return -1;
    }
    dpp_debug(DPP_DEBUG_ANY, "there are %d result(s) for 'netRole': %.*s\n",
              ntok, estr - sstr, sstr);
    if ((estr - sstr) > sizeof(peer->enrollee_role)) {
        strncpy(peer->enrollee_role, sstr, sizeof(peer->enrollee_role)-1);
    } else {
        strncpy(peer->enrollee_role, sstr, estr - sstr);
    }

    if (dpp_instance.enterprise) {
        if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                  &sstr, &estr, 1, "pkcs10")) < 1) {
            dpp_debug(DPP_DEBUG_TRACE, "provisioning enterprise credentials but no CSR\n");
            return 2;
        }
        dpp_debug(DPP_DEBUG_PKI, "there's %d result(s) of a CSR:\n %.*s\n",
                  ntok, estr - sstr, sstr);
        p10toca(peer, sstr, (int)(estr - sstr));
        // send the CSR off to the CA here!
        // when we get the cert back we set the status back to authenticated
        return 1;
    }

    if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                              &sstr, &estr, 1, "mudurl")) > 0) {
        dpp_debug(DPP_DEBUG_TRACE, "got a MUD URL of %.*s\n",
                  estr - sstr, sstr);
// TODO: when we handle pending responses do this
//        return SOMETHING
    }

    return 0;
}

int
process_dpp_config_frame (unsigned char field, unsigned char *data, int len, dpp_handle handle)
{
    gas_action_req_frame *garq;
    gas_action_resp_frame *garp;
    gas_action_comeback_resp_frame *gacrp;
    struct candidate *peer = NULL;
    int ret = -1;
    
    TAILQ_FOREACH(peer, &dpp_instance.peers, entry) {
        if (peer->handle == handle) {
            break;
        }
    }
    if (peer == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to find peer to do dpp!\n");
        return ret;
    }
    /*
     * got a DPP Config frame, got a peer, cancel the outstanding timer
     * and process the frame
     */
    srv_rem_timeout(srvctx, peer->t0);

    if (peer->core == DPP_CONFIGURATOR) {
        printf("processing config frame %s for peer in %s\n",
               field == GAS_INITIAL_REQUEST ? "initial request" :
               field == GAS_COMEBACK_REQUEST ? "comeback response" :
               field == BAD_DPP_SPEC_MESSAGE ? "config result" : "unknown",
               state_to_string(peer->state));

        switch (peer->state) {
            case DPP_AUTHENTICATED:
                if (field != GAS_INITIAL_REQUEST) {
                    dpp_debug(DPP_DEBUG_ERR, "Authenticated peer but peer didn't send INITIAL REQUEST\n");
                    break;
                }
                dpp_debug(DPP_DEBUG_TRACE, "got a GAS_INITIAL_REQUEST...\n");
                garq = (gas_action_req_frame *)data;
                if (memcmp(garq->ad_proto_elem, dpp_proto_elem_req, 2) ||
                    memcmp(garq->ad_proto_id, dpp_proto_id, sizeof(dpp_proto_id))) {
                    dpp_debug(DPP_DEBUG_ERR, "got an gas action frame, not a dpp config frame\n");
                    return ret;
                }
                peer->dialog_token = garq->dialog_token;
                ret = process_dpp_config_request(peer, garq->query_req, len - sizeof(gas_action_req_frame));
                switch (ret) {
                    case 0:
                        generate_dpp_config_resp_frame(peer, STATUS_OK);
                        peer->state = DPP_PROVISIONING;
                        break;
                    case 1:
                        peer->state = DPP_CA_RESP_PENDING;
                        break;
                    case 2:
                        /* don't advance the state, we're starting over */
                        generate_dpp_config_resp_frame(peer, STATUS_CSR_NEEDED);
                        break;
                    case 3:
                        /* don't advance the state, we're starting over here too! */
                        generate_dpp_config_resp_frame(peer, STATUS_NEW_KEY_NEEDED);
                        break;
                    default:
                        dpp_debug(DPP_DEBUG_ERR, "error processing DPP Config request!\n");
                        return ret;
                }
                (void)send_dpp_config_frame(peer, GAS_INITIAL_RESPONSE);
                peer->t0 = srv_add_timeout(srvctx, SRV_SEC(5), retransmit_config, peer);
                break;
            case DPP_PROVISIONING:
                switch (field) {
                    case GAS_COMEBACK_REQUEST:
                        dpp_debug(DPP_DEBUG_TRACE, "got a GAS_COMEBACK_REQUEST...\n");
                        /*
                         * this frame is not secured in any way, all we can do is send next fragment...
                         * ...check whether we've sent everything so we don't just continue to respond
                         * to these things ad infinitum
                         *
                         * set the timer so in case the client disappears we don't just sit here
                         * with a zombie peer, kill it after enough retransmissions
                         */
                        if (peer->nextfragment < peer->bufferlen) {
                            send_dpp_config_frame(peer, GAS_COMEBACK_RESPONSE);
                            /*
                             * if there's still more fragments we're telling the enrollee to come
                             * back immediately so set a shorter timeout. If we're done (and v2+)
                             * let the enrollee provision things and scan etc before coming back
                             * with the CONFIG RESULT
                             */
                            if (peer->nextfragment < peer->bufferlen) {
                                peer->t0 = srv_add_timeout(srvctx, SRV_SEC(5), retransmit_config, peer);
                            } else if (peer->version > 1) {
                                peer->t0 = srv_add_timeout(srvctx, SRV_SEC(10), retransmit_config, peer);
                            }
                        }
                        break;
                    case BAD_DPP_SPEC_MESSAGE:
                        dpp_debug(DPP_DEBUG_TRACE, "got a CONFIG_RESULT...\n");
                        /*
                         * this is not a GAS frame. Unfortunately the spec uses GAS for the
                         * request and response but a regular DPP action frame for the confirm.
                         * So overload the "field" (it's just a uchar) and special case it here
                         */
                        process_dpp_config_result(peer, data, len);
                        peer->state = DPP_PROVISIONED;
                        break;
                    default:
                        dpp_debug(DPP_DEBUG_ERR, "configurator in PROVISIONING but got a %d frame\n", field);
                        return ret;
                }
                break;
            case DPP_CA_RESP_PENDING:
                if (field != GAS_COMEBACK_REQUEST) {
                    dpp_debug(DPP_DEBUG_ERR, "waiting for CA response but got %d, not a COMEBACK REQUEST\n", field);
                    return ret;
                }
                dpp_debug(DPP_DEBUG_TRACE, "got a GAS_COMEBACK_REQUEST (we're still pending)...\n");
                send_dpp_config_frame(peer, GAS_COMEBACK_RESPONSE);
                /*
                 * set a timer here for the same reason we did it above, prevent zombies,
                 * but set it big so we don't retransmit while waiting for the CA
                 */
                peer->t0 = srv_add_timeout(srvctx, SRV_SEC(10), retransmit_config, peer);
                break;
            case DPP_PROVISIONED:
                dpp_debug(DPP_DEBUG_ERR, "already provisioned!\n");
                break;
            default:
                dpp_debug(DPP_DEBUG_ERR, "unknown state for DPP Config exchange: %s\n", peer->state);
        }
    } else {    /* enrollee */
        switch (peer->state) {
            case DPP_PROVISIONING:
                switch (field) {
                    case GAS_INITIAL_RESPONSE:
                        dpp_debug(DPP_DEBUG_TRACE, "got a GAS_INITIAL_RESPONSE...\n");
                        garp = (gas_action_resp_frame *)data;
                        if (memcmp(garp->ad_proto_elem, dpp_proto_elem_resp, 2) ||
                            memcmp(garp->ad_proto_id, dpp_proto_id, sizeof(dpp_proto_id))) {
                            dpp_debug(DPP_DEBUG_ERR, "got a gas action frame, not a dpp config frame\n");
                            return ret;
                        }
                        dpp_debug(DPP_DEBUG_TRACE, "response len is %d, comeback delay is %d\n",
                                  garp->query_resplen, garp->comeback_delay);
                        if (garp->comeback_delay) {
                            srv_add_timeout(srvctx, SRV_MSEC(garp->comeback_delay), cameback_delayed, peer);
                            return 1;
                        }
                        if (garp->query_resplen) {
                            /*
                             * if we got the query response then process it
                             */
                            if ((ret = process_dpp_config_response(peer, garp->query_resp,
                                                                   len - sizeof(gas_action_resp_frame))) < 0) {
                                dpp_debug(DPP_DEBUG_ERR, "error processing DPP Config response!\n");
                                return -1;
                            }
                            /*
                             * a ret of 0 means we already responded with a CSR or new key, don't want
                             * to send a config result in this case
                             */
                            if (ret > 0) {
                                if (peer->version > 1) {
                                    send_dpp_config_result(peer, STATUS_OK);
                                    peer->state = DPP_PROVISIONED;
                                }
                                (void)srv_add_timeout(srvctx, SRV_SEC(1), send_term_notice, peer);
                            }
                        } else if (garp->comeback_delay == 1) {
                            /*
                             * otherwise the response is going to be fragmented, ask for 1st fragment
                             */
                            send_dpp_config_frame(peer, GAS_COMEBACK_REQUEST);
                            peer->t0 = srv_add_timeout(srvctx, SRV_SEC(5), retransmit_config, peer);
                        }
                        break;
                    case GAS_COMEBACK_RESPONSE:
                        gacrp = (gas_action_comeback_resp_frame *)data;
                        dpp_debug(DPP_DEBUG_TRACE, "got a GAS_COMEBACK_RESPONSE... frag #%d\n", gacrp->fragment_id&0x7f);
                        if (peer->nextid &&
                            (peer->nextid != (gacrp->fragment_id&0x7f))) {
                            dpp_debug(DPP_DEBUG_ERR, "dropping fragment %d, already seen (%d)!\n", gacrp->fragment_id&0x7f,
                                      peer->nextid);
                            return -1;
                        }
                        peer->nextid = (int)(gacrp->fragment_id&0x7f) + 1;
                        dpp_debug(DPP_DEBUG_TRACE, "fragment id is %d, and next is %d\n",
                                  (int)(gacrp->fragment_id&0x7f), peer->nextid);
                        if (memcmp(gacrp->ad_proto_elem, dpp_proto_elem_resp, 2) ||
                            memcmp(gacrp->ad_proto_id, dpp_proto_id, sizeof(dpp_proto_id))) {
                            dpp_debug(DPP_DEBUG_ERR, "got an gas action frame, not a dpp config frame\n");
                            return -1;
                        }
                        if (gacrp->status_code) {
                            dpp_debug(DPP_DEBUG_ERR, "got a gas comeback response with status %d\n",
                                      gacrp->status_code);
                            return -1;
                        }
                        /*
                         * if we're being told to comeback later then come back later...
                         */
                        if (gacrp->comeback_delay) {
                            dpp_debug(DPP_DEBUG_TRACE, "told to come back in %d TUs\n", gacrp->comeback_delay);
                            srv_add_timeout(srvctx, SRV_MSEC(gacrp->comeback_delay), cameback_delayed, peer);
                            return 1;
                        }
                        if ((peer->nextfragment + gacrp->query_resplen) > sizeof(peer->buffer)) {
                            dpp_debug(DPP_DEBUG_ERR, "a bit too many fragments\n");
                        }
                        /*
                         * use the buffer and next fragment field since the enrollee is not using it
                         */
                        memcpy(peer->buffer + peer->nextfragment, gacrp->query_resp, gacrp->query_resplen);
                        peer->nextfragment += gacrp->query_resplen;
                        dpp_debug(DPP_DEBUG_TRACE, "getting another %d fragment, total so far is %d\n",
                                  gacrp->query_resplen, peer->nextfragment);
                        /*
                         * if there's more fragments then ask for them, otherwise process the frame
                         */
                        if (gacrp->fragment_id & 0x80) {
                            dpp_debug(DPP_DEBUG_TRACE, "ask for next fragment\n");
                            send_dpp_config_frame(peer, GAS_COMEBACK_REQUEST);
                            peer->t0 = srv_add_timeout(srvctx, SRV_SEC(5), retransmit_config, peer);
                        } else {
                            dpp_debug(DPP_DEBUG_TRACE, "final fragment, %d total\n", peer->nextfragment);
                            if (process_dpp_config_response(peer, peer->buffer, peer->nextfragment) < 1) {
                                dpp_debug(DPP_DEBUG_ERR, "error processing DPP Config response!\n");
                                return -1;
                            }
                            if (peer->version > 1) {
                                send_dpp_config_result(peer, STATUS_OK);
                            }
                            (void)srv_add_timeout(srvctx, SRV_SEC(1), send_term_notice, peer);
                        }
                        break;
                }
                break;
            case DPP_PROVISIONED:
                dpp_debug(DPP_DEBUG_ERR, "Already provisioned, got a %d frame...\n", field);
                send_dpp_config_result(peer, STATUS_OK);
                break;
            case DPP_CA_RESP_PENDING:
            case DPP_AUTHENTICATED:
                break;
            default:
                dpp_debug(DPP_DEBUG_ERR, "unknown state for DPP Config exchange: %d\n", peer->state);
        }
    }

    return 1;
}

/*
 * timers set by the Configurator and Enrollee, respectively, to transition
 * to the DPP Config protocol
 */
static void
no_peer (timerid id, void *data)
{
    dpp_debug(DPP_DEBUG_ERR, "Enrollee did not begin DPP Config protocol...bailing!\n");
    fail_dpp_peer((struct candidate *)data);
}

static void
start_config_protocol (timerid id, void *data)
{
    struct candidate *peer = (struct candidate *)data;
    dpp_debug(DPP_DEBUG_TRACE, "beginning DPP Config protocol\n");
    peer->nextid = 0;
    memset(peer->frame, 0, peer->mtu);
    send_dpp_config_req_frame(peer);
    peer->state = DPP_PROVISIONING;
}

//----------------------------------------------------------------------
// DPP authentication exchange routines
//----------------------------------------------------------------------

static int
generate_auth (struct candidate *peer, int initiators, unsigned char *auth)
{
    int offset;
    BIGNUM *x = NULL;
    unsigned char *xoctets = NULL, finaloctet;
    unsigned int mdlen = 0;
    EVP_MD_CTX *mdctx = NULL;
    const EC_POINT *boot, *pub;
    
    if (((x = BN_new()) == NULL) || ((mdctx = EVP_MD_CTX_new()) == NULL) ||
        ((xoctets = (unsigned char *)malloc(dpp_instance.primelen)) == NULL)) {
        goto fin;
    }

    EVP_DigestInit(mdctx, dpp_instance.hashfcn);
    finaloctet = initiators;
    if (initiators != peer->is_initiator) {
        EVP_DigestUpdate(mdctx, peer->mynonce, dpp_instance.noncelen);
        debug_buffer(DPP_DEBUG_TRACE, "my nonce", peer->mynonce, dpp_instance.noncelen);
        EVP_DigestUpdate(mdctx, peer->peernonce, dpp_instance.noncelen);
        debug_buffer(DPP_DEBUG_TRACE, "peer nonce", peer->peernonce, dpp_instance.noncelen);

        if ((pub = EC_KEY_get0_public_key(peer->my_proto)) == NULL) {
            goto fin;
        }
        if (!EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, pub,
                                             x, NULL, bnctx)) {
            goto fin;
        }
        memset(xoctets, 0, dpp_instance.primelen);
        offset = dpp_instance.primelen - BN_num_bytes(x);
        BN_bn2bin(x, xoctets + offset);
        EVP_DigestUpdate(mdctx, xoctets, dpp_instance.primelen);
        debug_buffer(DPP_DEBUG_TRACE, "my proto pubkey", xoctets, dpp_instance.primelen);

        if (!EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, peer->peer_proto,
                                             x, NULL, bnctx)) {
            goto fin;
        }
        memset(xoctets, 0, dpp_instance.primelen);
        offset = dpp_instance.primelen - BN_num_bytes(x);
        BN_bn2bin(x, xoctets + offset);
        EVP_DigestUpdate(mdctx, xoctets, dpp_instance.primelen);
        debug_buffer(DPP_DEBUG_TRACE, "peer's proto pubkey", xoctets, dpp_instance.primelen);
        /*
         * if we're doing mutual auth then this is always "my" bootstrapping key
         */
        if (peer->mauth) {
            if (((boot = EC_KEY_get0_public_key(dpp_instance.bootstrap)) == NULL) ||
                !EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, boot,
                                                     x, NULL, bnctx)) {
                goto fin;
            }
            memset(xoctets, 0, dpp_instance.primelen);
            offset = dpp_instance.primelen - BN_num_bytes(x);
            BN_bn2bin(x, xoctets + offset);
            EVP_DigestUpdate(mdctx, xoctets, dpp_instance.primelen);
            debug_buffer(DPP_DEBUG_TRACE, "my bootstrap pubkey", xoctets, dpp_instance.primelen);
        }
        /*
         * however, if we're not doing mutual authentication then when I'm the responder
         * this is my bootstrapping key and when I'm not this is the peer's bootstrapping key
         */
        if (!peer->mauth && !peer->is_initiator) {
            if (((boot = EC_KEY_get0_public_key(dpp_instance.bootstrap)) == NULL) ||
                !EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, boot,
                                                     x, NULL, bnctx)) {
                goto fin;
            }
        } else {
            if (((boot = EC_KEY_get0_public_key(peer->peer_bootstrap)) == NULL) ||
                !EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, boot,
                                                     x, NULL, bnctx)) {
                goto fin;
            }
        }
        
        memset(xoctets, 0, dpp_instance.primelen);
        offset = dpp_instance.primelen - BN_num_bytes(x);
        BN_bn2bin(x, xoctets + offset);
        EVP_DigestUpdate(mdctx, xoctets, dpp_instance.primelen);
        debug_buffer(DPP_DEBUG_TRACE, !peer->mauth && !peer->is_initiator ? "my bootstrap pubkey" : "peer's bootstrap pubkey",
                     xoctets, dpp_instance.primelen);
    } else {
        EVP_DigestUpdate(mdctx, peer->peernonce, dpp_instance.noncelen);
        debug_buffer(DPP_DEBUG_TRACE, "peer nonce", peer->peernonce, dpp_instance.noncelen);
        EVP_DigestUpdate(mdctx, peer->mynonce, dpp_instance.noncelen);
        debug_buffer(DPP_DEBUG_TRACE, "my nonce", peer->mynonce, dpp_instance.noncelen);

        if (!EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, peer->peer_proto,
                                             x, NULL, bnctx)) {
            goto fin;
        }
        memset(xoctets, 0, dpp_instance.primelen);
        offset = dpp_instance.primelen - BN_num_bytes(x);
        BN_bn2bin(x, xoctets + offset);
        EVP_DigestUpdate(mdctx, xoctets, dpp_instance.primelen);
        debug_buffer(DPP_DEBUG_TRACE, "peer proto pubkey", xoctets, dpp_instance.primelen);

        if ((pub = EC_KEY_get0_public_key(peer->my_proto)) == NULL) {
            goto fin;
        }
        if (!EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, pub,
                                             x, NULL, bnctx)) {
            goto fin;
        }
        memset(xoctets, 0, dpp_instance.primelen);
        offset = dpp_instance.primelen - BN_num_bytes(x);
        BN_bn2bin(x, xoctets + offset);
        EVP_DigestUpdate(mdctx, xoctets, dpp_instance.primelen);
        debug_buffer(DPP_DEBUG_TRACE, "my proto pubkey", xoctets, dpp_instance.primelen);
        /*
         * if we're doing mutual authentication then this is always the peer's bootstrapping
         * key
         */
        if (peer->mauth) {
            if (((boot = EC_KEY_get0_public_key(peer->peer_bootstrap)) == NULL) ||
                !EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, boot,
                                                     x, NULL, bnctx)) {
                goto fin;
            }
            memset(xoctets, 0, dpp_instance.primelen);
            offset = dpp_instance.primelen - BN_num_bytes(x);
            BN_bn2bin(x, xoctets + offset);
            EVP_DigestUpdate(mdctx, xoctets, dpp_instance.primelen);
            debug_buffer(DPP_DEBUG_TRACE, "peer bootstrap pubkey", xoctets, dpp_instance.primelen);
        }
        /*
         * however, if we're not doing mutual authenticaiton then when I'm the initiator
         * this is the peer's bootstrapping key and when I'm not this is my bootstrapping key
         */
        if (!peer->mauth && peer->is_initiator) {
            if (((boot = EC_KEY_get0_public_key(peer->peer_bootstrap)) == NULL) ||
                !EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, boot,
                                                     x, NULL, bnctx)) {
                goto fin;
            }
        } else {
            if (((boot = EC_KEY_get0_public_key(dpp_instance.bootstrap)) == NULL) ||
                !EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, boot,
                                                     x, NULL, bnctx)) {
                goto fin;
            }
        }
        memset(xoctets, 0, dpp_instance.primelen);
        offset = dpp_instance.primelen - BN_num_bytes(x);
        BN_bn2bin(x, xoctets + offset);
        EVP_DigestUpdate(mdctx, xoctets, dpp_instance.primelen);
        debug_buffer(DPP_DEBUG_TRACE, !peer->mauth && peer->is_initiator ? "peer's bootstrap pubkey" : "my bootstrap pubkey",
                     xoctets, dpp_instance.primelen);
    }
    EVP_DigestUpdate(mdctx, &finaloctet, 1);
    debug_buffer(DPP_DEBUG_TRACE, "final octet", &finaloctet, 1);
    mdlen = dpp_instance.digestlen;
    EVP_DigestFinal(mdctx, auth, &mdlen);

fin:
    if (x != NULL) {
        BN_free(x);
    }
    if (mdctx != NULL) {
        EVP_MD_CTX_free(mdctx);
    }
    if (xoctets != NULL) {
        free(xoctets);
    }
    return mdlen;
}


static int
compute_ke (struct candidate *peer, BIGNUM *n, BIGNUM *l)
{
    int offset;
    unsigned char salt[SHA512_DIGEST_LENGTH], *ikm, *ptr;

    if ((ikm = (unsigned char *)malloc(3 * dpp_instance.primelen)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to malloc space to compute ke!\n");
        return 0;
    }
    /*
     * construct ikm as (M.x | N.x | L.x)
     */
    memset(ikm, 0, (3 * dpp_instance.primelen));
    ptr = ikm;
    offset = dpp_instance.primelen - BN_num_bytes(peer->m);
    BN_bn2bin(peer->m, ptr + offset);
    ptr += dpp_instance.primelen;
    offset = dpp_instance.primelen - BN_num_bytes(n);
    BN_bn2bin(n, ptr + offset);
    ptr += dpp_instance.primelen;
    if (peer->mauth && l != NULL) {
        offset = dpp_instance.primelen - BN_num_bytes(l);
        BN_bn2bin(l, ptr + offset);
    }
    
    /*
     * salt is the length of the largest hash digest supported, since nonces
     * are half the length of the hash digest it's the right size
     */
    if (peer->is_initiator) {
        memcpy(salt, peer->mynonce, dpp_instance.noncelen);
        memcpy(salt+dpp_instance.noncelen, peer->peernonce, dpp_instance.noncelen);
    } else {
        memcpy(salt, peer->peernonce, dpp_instance.noncelen);
        memcpy(salt+dpp_instance.noncelen, peer->mynonce, dpp_instance.noncelen);
    }
    /*
     * and compute bk and ke from ikm
     */
    if (peer->mauth && l != NULL) {
        hkdf_extract(dpp_instance.hashfcn,
                     salt, 2*dpp_instance.noncelen,
                     ikm, 3*dpp_instance.primelen,
                     peer->bk);
        hkdf_expand(dpp_instance.hashfcn,
                    peer->bk, dpp_instance.digestlen,
                    (unsigned char *)"DPP Key", strlen("DPP Key"),
                    peer->ke, dpp_instance.digestlen);
    } else {
        hkdf_extract(dpp_instance.hashfcn,
                     salt, 2*dpp_instance.noncelen,
                     ikm, 2*dpp_instance.primelen,
                     peer->bk);
        hkdf_expand(dpp_instance.hashfcn,
                    peer->bk, dpp_instance.digestlen,
                    (unsigned char *)"DPP Key", strlen("DPP Key"),
                    peer->ke, dpp_instance.digestlen);
    }
    if (ikm != NULL) {
        free(ikm);
    }
    return 1;
}

//----------------------------------------------------------------------
// transmitting routines for initiator and responder
//----------------------------------------------------------------------

static int
send_dpp_auth_confirm (struct candidate *peer, unsigned char status)
{
    unsigned char bootkeyhash[SHA256_DIGEST_LENGTH], *ptr, *attrs, *end;
    siv_ctx ctx;
    TLV *tlv;
    int success = 0, aadlen = 0;

    memset(peer->buffer, 0, sizeof(peer->buffer));
    peer->bufferlen = 0;
    attrs = peer->buffer;
    tlv = (TLV *)attrs;

    /*
     * status...
     */
    tlv = TLV_set_tlv(tlv, DPP_STATUS, 1, &status);
    /*
     * H(Br)...
     */
    if (compute_bootstrap_key_hash(peer->peer_bootstrap, bootkeyhash) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "unable to compute bootstrap hash for DPP Auth init\n");
        goto fin;
    }
    tlv = TLV_set_tlv(tlv, RESPONDER_BOOT_HASH, SHA256_DIGEST_LENGTH, bootkeyhash);

    if (peer->mauth) {
        /*
         * ...then H(Bi)
         */
        if (compute_bootstrap_key_hash(dpp_instance.bootstrap, bootkeyhash) < 1) {
            dpp_debug(DPP_DEBUG_ERR, "unable to compute bootstrap hash for DPP Auth init\n");
            goto fin;
        }
        tlv = TLV_set_tlv(tlv, INITIATOR_BOOT_HASH, SHA256_DIGEST_LENGTH, bootkeyhash);
    }
    
    aadlen = (unsigned char *)tlv - attrs;
    /*
     * and finally wrapped data
     */
    tlv->type = WRAPPED_DATA;
    if (status == STATUS_OK) {
        tlv->length = (sizeof(TLV) + AES_BLOCK_SIZE + dpp_instance.digestlen);
    } else {
        tlv->length = (sizeof(TLV) + AES_BLOCK_SIZE + dpp_instance.noncelen);
    }

    ptr = tlv->value;
    /*
     * ...which is itself a TLV, the initiator auth tag
     */
    tlv = (TLV *)(ptr + AES_BLOCK_SIZE);

    /*
     * set up the DPP action frame header for inclusion as part of AAD
     */
    setup_dpp_action_frame(peer, DPP_SUB_AUTH_CONFIRM);
    if (status == STATUS_OK) {
        /*
         * only 1 attribute to ieee-ize...
         */
        tlv->type = ieee_order(INITIATOR_AUTH_TAG);
        tlv->length = ieee_order(dpp_instance.digestlen);
        end = (unsigned char *)(tlv->value + dpp_instance.digestlen);

        dpp_debug(DPP_DEBUG_TRACE, "I-auth...\n");  // delete this
        if (generate_auth(peer, 1, tlv->value) != dpp_instance.digestlen) {
            goto fin;
        }
        debug_buffer(DPP_DEBUG_TRACE, "AUTHi", tlv->value, dpp_instance.digestlen);
        fflush(stdout);

        peer->bufferlen = (int)(end - attrs);
        /*
         * since we're binding the inner encryption to the cleartext attributes
         * make sure we're authenticating what's sent
         */
        ieeeize_hton_attributes(attrs, peer->bufferlen);

        switch(dpp_instance.digestlen) {
            case SHA256_DIGEST_LENGTH:
                siv_init(&ctx, peer->ke, SIV_256);
                break;
            case SHA384_DIGEST_LENGTH:
                siv_init(&ctx, peer->ke, SIV_384);
                break;
            case SHA512_DIGEST_LENGTH:
                siv_init(&ctx, peer->ke, SIV_512);
                break;
            default:
                dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", dpp_instance.digestlen);
                goto fin;
        }
        siv_encrypt(&ctx, ptr + AES_BLOCK_SIZE, ptr + AES_BLOCK_SIZE,
                    dpp_instance.digestlen + sizeof(TLV), ptr, 
                    2, peer->frame, sizeof(dpp_action_frame), attrs, aadlen);
    } else {
        /*
         * status is NOT OK!
         *
         * only 1 attribute to ieee-ize...
         */
        tlv->type = ieee_order(RESPONDER_NONCE);
        tlv->length = ieee_order(dpp_instance.noncelen);
        memcpy(tlv->value, peer->peernonce, dpp_instance.noncelen);
        end = (unsigned char *)(tlv->value + dpp_instance.noncelen);

        peer->bufferlen = (int)(end - attrs);
        /*
         * since we're binding the inner encryption to the cleartext attributes
         * make sure we're authenticating what's sent
         */
        ieeeize_hton_attributes(attrs, peer->bufferlen);

        switch(dpp_instance.digestlen) {
            case SHA256_DIGEST_LENGTH:
                siv_init(&ctx, peer->k2, SIV_256);
                break;
            case SHA384_DIGEST_LENGTH:
                siv_init(&ctx, peer->k2, SIV_384);
                break;
            case SHA512_DIGEST_LENGTH:
                siv_init(&ctx, peer->k2, SIV_512);
                break;
            default:
                dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", dpp_instance.digestlen);
                goto fin;
        }
        siv_encrypt(&ctx, ptr + AES_BLOCK_SIZE, ptr + AES_BLOCK_SIZE,
                    dpp_instance.digestlen + sizeof(TLV), ptr, 
                    2, peer->frame, sizeof(dpp_action_frame), attrs, aadlen);
    }
    if (send_dpp_action_frame(peer)) {
        success = 1;
        peer->retrans = 0;
    }
    
fin:
    return success;
}

static int
send_dpp_auth_response (struct candidate *peer, unsigned char status)
{
    siv_ctx ctx;
    unsigned char *n1 = NULL;
    unsigned char bootkeyhash[SHA256_DIGEST_LENGTH], *ptr, capabilities;
    unsigned char *primary, *secondary, *attrs;
    const EC_POINT *Pr, *Bi;
    const BIGNUM *pr, *br;
    EC_POINT *N = NULL, *L = NULL;
    BIGNUM *x = NULL, *y = NULL, *n = NULL, *l = NULL, *priv = NULL, *order =NULL;
    TLV *tlv, *primarywrap, *secondarywrap;
    int offset, success = 0, primarywraplen;

    capabilities = peer->core;
    if (status == STATUS_OK) {
        if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) || ((n = BN_new()) == NULL) ||
            ((N = EC_POINT_new(dpp_instance.group)) == NULL) || ((order = BN_new()) == NULL)) {
            dpp_debug(DPP_DEBUG_ERR, "unable to create bignums to construct DPP Auth Resp!\n");
            goto fin;
        }
        /*
         * only needed if we're doing mutual authentication
         */
        if (peer->mauth) {
            if (((priv = BN_new()) == NULL) ||
                ((l = BN_new()) == NULL) || ((L = EC_POINT_new(dpp_instance.group)) == NULL)) {
                goto fin;
            }
        }

        if (((peer->my_proto = EC_KEY_new_by_curve_name(dpp_instance.nid)) == NULL) ||
            !EC_KEY_generate_key(peer->my_proto) ||
            ((Pr = EC_KEY_get0_public_key(peer->my_proto)) == NULL) ||
            ((pr = EC_KEY_get0_private_key(peer->my_proto)) == NULL) ||
            !EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, Pr, x, y, bnctx)) {
            dpp_debug(DPP_DEBUG_ERR, "unable to create protocol key to initiate DPP!\n");
            goto fin;
        }
        debug_a_bignum(DPP_DEBUG_TRACE, "pr", (BIGNUM *)pr);
        debug_ec_key(DPP_DEBUG_TRACE, "Pr", peer->my_proto);

        if (!EC_POINT_mul(dpp_instance.group, N, NULL, peer->peer_proto, pr, bnctx) ||
            !EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, N, n, NULL, bnctx)) {
            dpp_debug(DPP_DEBUG_ERR, "unable to compute N!\n");
            goto fin;
        }
        if ((n1 = (unsigned char *)malloc(dpp_instance.primelen)) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "unable to malloc data to compute k2\n");
            goto fin;
        }
        memset(n1, 0, dpp_instance.primelen);
        offset = dpp_instance.primelen - BN_num_bytes(n);
        BN_bn2bin(n, n1 + offset);
        hkdf(dpp_instance.hashfcn, 0, n1, dpp_instance.primelen, NULL, 0,
             (unsigned char *)"second intermediate key", strlen("second intermediate key"),
             peer->k2, dpp_instance.digestlen);

        debug_buffer(DPP_DEBUG_TRACE, "k2", peer->k2, dpp_instance.digestlen);

        if (!RAND_bytes(peer->mynonce, dpp_instance.noncelen)) {
            dpp_debug(DPP_DEBUG_ERR, "unable to obtain entropy for nonce!\n");
            goto fin;
        }
        if (peer->mauth) {
            /*
             * For the responder, L = (br + pr) modq * Bi
             */
            if (((br = EC_KEY_get0_private_key(dpp_instance.bootstrap)) == NULL) ||
                ((Bi = EC_KEY_get0_public_key(peer->peer_bootstrap)) == NULL) ||
                !EC_GROUP_get_order(dpp_instance.group, order, bnctx)) {
                goto fin;
            }
            BN_add(priv, br, pr);
            BN_mod(priv, priv, order, bnctx);   /* priv = (br + pr) mod q */
            if (!EC_POINT_mul(dpp_instance.group, L, NULL, Bi, priv, bnctx) ||
                !EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, L, l, NULL, bnctx)) {
                dpp_debug(DPP_DEBUG_ERR, "DPP responder unable to compute L!\n");
                goto fin;
            }
            if (!compute_ke(peer, n, l)) {
                dpp_debug(DPP_DEBUG_ERR, "unable to compute ke!\n");
                goto fin;
            }
        } else {
            if (!compute_ke(peer, n, NULL)) {
                dpp_debug(DPP_DEBUG_ERR, "unable to compute ke!\n");
                goto fin;
            }
        }
        
        debug_buffer(DPP_DEBUG_TRACE, "responder nonce", peer->mynonce, dpp_instance.noncelen);
        debug_buffer(DPP_DEBUG_TRACE, "ke", peer->ke, dpp_instance.digestlen);
    }
        
    /*
     * start building the response...
     */
    memset(peer->buffer, 0, sizeof(peer->buffer));
    peer->bufferlen = 0;
    attrs = peer->buffer;
    tlv = (TLV *)attrs;
    /*
     * a status TLV, whatever was passed in
     */
    tlv = TLV_set_tlv(tlv, DPP_STATUS, 1, &status);
    /*
     * responder bootstrap hash then initiator bootstrap hash
     */
    if (compute_bootstrap_key_hash(dpp_instance.bootstrap, bootkeyhash) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "unable to compute bootstrap hash to parse Auth Request\n");
        goto fin;
    }
    tlv = TLV_set_tlv(tlv, RESPONDER_BOOT_HASH, SHA256_DIGEST_LENGTH, bootkeyhash);

    /*
     * if we're doing mutual authentication then add a hash of the initiator's bootstrap key
     */
    if (peer->mauth) {
        if (compute_bootstrap_key_hash(peer->peer_bootstrap, bootkeyhash) < 1) {
            dpp_debug(DPP_DEBUG_ERR, "unable to compute bootstrap hash to parse Auth Request\n");
            goto fin;
        }
        tlv = TLV_set_tlv(tlv, INITIATOR_BOOT_HASH, SHA256_DIGEST_LENGTH, bootkeyhash);
    }

    /*
     * negotiate the version if the peer supports v2.0 or later
     */
    if (peer->version > 1) {
        tlv  = TLV_set_tlv(tlv, PROTOCOL_VERSION, 1, &peer->version);
    }
    
    /*
     * if status is not OK then there is no protocol key
     */
    if (status == STATUS_OK) {
        /*
         * responder protocol key (x,y)
         */
        tlv->type = RESPONDER_PROTOCOL_KEY;
        tlv->length = 2 * dpp_instance.primelen;
        ptr = tlv->value;
        offset = dpp_instance.primelen - BN_num_bytes(x);
        BN_bn2bin(x, ptr + offset);
        ptr += dpp_instance.primelen;
        offset = dpp_instance.primelen - BN_num_bytes(y);
        BN_bn2bin(y, ptr + offset);
        tlv = TLV_next(tlv);
    }
    /*
     * if the peer sent us a verion > 1 then respond 
     */
    if (peer->version > 1) {
        tlv = TLV_set_tlv(tlv, PROTOCOL_VERSION, 1, &peer->version);
    }
    /*
     * the primary wrapping of data which is...
     */
    tlv->type = WRAPPED_DATA;
    primary = tlv->value;
    primarywrap = (TLV *)(primary + AES_BLOCK_SIZE);
    /*
     * the two nonces
     */
    if (status == STATUS_OK) {
        primarywrap = TLV_set_tlv(primarywrap, RESPONDER_NONCE,
                                  dpp_instance.noncelen, peer->mynonce);
    }
    primarywrap = TLV_set_tlv(primarywrap, INITIATOR_NONCE,
                              dpp_instance.noncelen, peer->peernonce);
    /*
     * the capabilities of the responder
     */
    primarywrap = TLV_set_tlv(primarywrap, RESPONDER_CAPABILITIES, 1, &capabilities);

    /*
     * fill in the DPP Auth frame header for inclusion as a component of AAD
     */
    setup_dpp_action_frame(peer, DPP_SUB_AUTH_RESPONSE);
    if (status == STATUS_OK) {
        /*
         * and secondary wrapped data which is
         */
        primarywrap->type = WRAPPED_DATA;
        secondary = primarywrap->value;
        /*
         * the responder auth data
         */
        secondarywrap = (TLV *)(secondary + AES_BLOCK_SIZE);
        secondarywrap->type = ieee_order(RESPONDER_AUTH_TAG);
        secondarywrap->length = ieee_order(dpp_instance.digestlen);
        dpp_debug(DPP_DEBUG_TRACE, "R-auth...\n");   // delete this
        if (generate_auth(peer, 0, secondarywrap->value) != dpp_instance.digestlen) {
            goto fin;
        }

        debug_buffer(DPP_DEBUG_TRACE, "AUTHr", secondarywrap->value, dpp_instance.digestlen);
    
        /*
         * compute the actual end of this wrapping of wrappings
         * and fill in the dangling TLV lengths
         */
        ptr = secondarywrap->value + dpp_instance.digestlen;
        primarywrap->length = ptr - primarywrap->value;
        primarywraplen = tlv->length = ptr - primary;

        /*
         * now encrypt the secondary wrapping in ke
         */
        switch(dpp_instance.digestlen) {
            case SHA256_DIGEST_LENGTH:
                siv_init(&ctx, peer->ke, SIV_256);
                break;
            case SHA384_DIGEST_LENGTH:
                siv_init(&ctx, peer->ke, SIV_384);
                break;
            case SHA512_DIGEST_LENGTH:
                siv_init(&ctx, peer->ke, SIV_512);
                break;
            default:
                dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", dpp_instance.digestlen);
                goto fin;
        }
        /*
         * no AAD in this inner wrapped data
         */
        siv_encrypt(&ctx, (unsigned char *)secondarywrap, (unsigned char *)secondarywrap,
                    primarywrap->length - AES_BLOCK_SIZE, secondary, 0);
        /*
         * now ieee-ize the TLVs in the primary wrapping
         */
        ieeeize_hton_attributes(primary + AES_BLOCK_SIZE, (int)(ptr - (primary + AES_BLOCK_SIZE)));
        /*
         * and encrypt the whole thing with k2
         */
        switch(dpp_instance.digestlen) {
            case SHA256_DIGEST_LENGTH:
                siv_init(&ctx, peer->k2, SIV_256);
                break;
            case SHA384_DIGEST_LENGTH:
                siv_init(&ctx, peer->k2, SIV_384);
                break;
            case SHA512_DIGEST_LENGTH:
                siv_init(&ctx, peer->k2, SIV_512);
                break;
            default:
                dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", dpp_instance.digestlen);
                goto fin;
        }
        siv_encrypt(&ctx, primary + AES_BLOCK_SIZE, primary + AES_BLOCK_SIZE,
                    primarywraplen - AES_BLOCK_SIZE, primary, 
                    2, peer->frame, sizeof(dpp_action_frame), attrs, ((unsigned char *)tlv - attrs));
    } else {
        /*
         * STATUS is not OK!
         *
         * fix up the lengths we skipped over and send back a notification
         */
        ptr = (unsigned char *)primarywrap;
        tlv->length = primarywraplen = ptr - primary;

        /*
         * now ieee-ize the TLVs in the primary wrapping
         */
        ieeeize_hton_attributes(primary + AES_BLOCK_SIZE, (int)(ptr - (primary + AES_BLOCK_SIZE)));
        
        switch(dpp_instance.digestlen) {
            case SHA256_DIGEST_LENGTH:
                siv_init(&ctx, peer->k1, SIV_256);
                break;
            case SHA384_DIGEST_LENGTH:
                siv_init(&ctx, peer->k1, SIV_384);
                break;
            case SHA512_DIGEST_LENGTH:
                siv_init(&ctx, peer->k1, SIV_512);
                break;
            default:
                dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", dpp_instance.digestlen);
                goto fin;
        }
        siv_encrypt(&ctx, primary + AES_BLOCK_SIZE, primary + AES_BLOCK_SIZE,
                    primarywraplen - AES_BLOCK_SIZE, primary,
                    2, peer->frame, sizeof(dpp_action_frame), attrs, ((unsigned char *)tlv - attrs));
    }
    
    peer->bufferlen = (int)(ptr - peer->buffer);
    if (send_dpp_action_frame(peer)) {
        success = 1;
        peer->retrans = 0;
        peer->t0 = srv_add_timeout(srvctx, SRV_SEC(2), retransmit_auth, peer);
    }
    
fin:
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
    if (n != NULL) {
        BN_free(n);
    }
    if (l != NULL) {
        BN_free(l);
    }
    if (priv != NULL) {
        BN_free(priv);
    }
    if (order != NULL) {
        BN_free(order);
    }
    if (n1 != NULL) {
        free(n1);
    }
    if (N != NULL) {
        EC_POINT_free(N);
    }
    if (L != NULL) {
        EC_POINT_free(L);
    }
    return success;
}

static int
send_dpp_auth_request (struct candidate *peer)
{
    siv_ctx ctx;
    unsigned char wrap[SHA512_DIGEST_LENGTH + 1], *attrs;
    unsigned char bootkeyhash[SHA256_DIGEST_LENGTH], *ptr, capabilities;
    const EC_POINT *pub = NULL, *pt = NULL;
    const BIGNUM *priv;
    unsigned short wrapped_len;
    EC_POINT *M = NULL;
    BIGNUM *x = NULL, *y = NULL;
    unsigned char *m1 = NULL;
    TLV *tlv;
    int offset, success = 0;

    peer->bufferlen = 0;
    memset(peer->buffer, 0, sizeof(peer->buffer));
    attrs = peer->buffer;

    if (peer->peer_bootstrap == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "no peer bootstrapping key, cannot initiate DPP Auth!\n");
        goto fin;
    }
    if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
        ((M = EC_POINT_new(dpp_instance.group)) == NULL)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to create bignums to initiate DPP!\n");
        goto fin;
    }
    if (((peer->my_proto = EC_KEY_new_by_curve_name(dpp_instance.nid)) == NULL) ||
        !EC_KEY_generate_key(peer->my_proto) ||
        ((pub = EC_KEY_get0_public_key(peer->my_proto)) == NULL) ||
        ((priv = EC_KEY_get0_private_key(peer->my_proto)) == NULL) ||
        ((pt = EC_KEY_get0_public_key(peer->peer_bootstrap)) == NULL) ||
        !EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, pub, x, y, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to create protocol key to initiate DPP!\n");
        goto fin;
    }

    debug_a_bignum(DPP_DEBUG_TRACE, "pi", (BIGNUM *)priv);
    debug_ec_key(DPP_DEBUG_TRACE, "Pi", peer->my_proto);

    /*
     * compute k1
     */
    if (!EC_POINT_mul(dpp_instance.group, M, NULL, pt, priv, bnctx) ||
        !EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, M, peer->m, NULL, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to compute M to initiate DPP!\n");
        goto fin;
    }
    if ((m1 = (unsigned char *)malloc(dpp_instance.primelen)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to allocate m1 to initiate DPP!\n");
        goto fin;
    }
    memset(m1, 0, dpp_instance.primelen);
    offset = dpp_instance.primelen - BN_num_bytes(peer->m);
    BN_bn2bin(peer->m, m1 + offset);
    hkdf(dpp_instance.hashfcn, 0,
         m1, dpp_instance.primelen,
         NULL, 0,
         (unsigned char *)"first intermediate key", strlen("first intermediate key"),
         peer->k1, dpp_instance.digestlen);

    debug_buffer(DPP_DEBUG_TRACE, "k1", peer->k1, dpp_instance.digestlen);
    
    switch(dpp_instance.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, peer->k1, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, peer->k1, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, peer->k1, SIV_512);
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", dpp_instance.digestlen);
            goto fin;
    }

    /*
     * get our wrapped TLVs set up
     */
    if (!RAND_bytes(peer->mynonce, dpp_instance.noncelen)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to obtain entropy for nonce!\n");
        goto fin;
    }

    debug_buffer(DPP_DEBUG_TRACE, "initiator nonce", peer->mynonce, dpp_instance.noncelen);
    
    dpp_debug(DPP_DEBUG_TRACE, "offering role: %s\n", dpp_instance.core == DPP_CONFIGURATOR ? "configurator" : \
              dpp_instance.core == DPP_ENROLLEE ? "enrollee" : \
              dpp_instance.core == (DPP_CONFIGURATOR|DPP_ENROLLEE) ? "both" : "unknown");

    capabilities = dpp_instance.core;

    tlv = (TLV *)wrap;
    tlv = TLV_set_tlv(tlv, INITIATOR_NONCE, dpp_instance.noncelen, peer->mynonce);
    ptr = (unsigned char *)TLV_set_tlv(tlv, INITIATOR_CAPABILITIES, 1, &capabilities);
    wrapped_len = ptr - wrap;
    /*
     * put the attributes to-be-wrapped into ieee_order()
     */
    ieeeize_hton_attributes(wrap, wrapped_len);

    /*
     * Now cons up a DPP Authentication Initiate. First H(Br)...
     */
    tlv = (TLV *)attrs;
    if (compute_bootstrap_key_hash(peer->peer_bootstrap, bootkeyhash) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "unable to compute bootstrap hash for DPP Auth init\n");
        goto fin;
    }
    tlv = TLV_set_tlv(tlv, RESPONDER_BOOT_HASH, SHA256_DIGEST_LENGTH, bootkeyhash);
    /*
     * ...then H(Bi)
     */
    if (compute_bootstrap_key_hash(dpp_instance.bootstrap, bootkeyhash) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "unable to compute bootstrap hash for DPP Auth init\n");
        goto fin;
    }

    tlv = TLV_set_tlv(tlv, INITIATOR_BOOT_HASH, SHA256_DIGEST_LENGTH, bootkeyhash);
    /*
     * ...followed by my protocol key
     */
    tlv->type = INITIATOR_PROTOCOL_KEY;
    tlv->length = 2 * dpp_instance.primelen;
    ptr = tlv->value;
    offset = dpp_instance.primelen - BN_num_bytes(x);
    BN_bn2bin(x, ptr + offset);
    ptr += dpp_instance.primelen;
    offset = dpp_instance.primelen - BN_num_bytes(y);
    BN_bn2bin(y, ptr + offset);
    tlv = TLV_next(tlv);

    dpp_debug(DPP_DEBUG_TRACE, "version is %d in send_dpp_auth_request\n", peer->version);
    if (peer->version > 1) {
        dpp_debug(DPP_DEBUG_TRACE, "adding a version...\n");
        tlv = TLV_set_tlv(tlv, PROTOCOL_VERSION, 1, &peer->version);
    }
    
    /*
     * if we want to change channels and get the response on a different
     * one, indicate that now...
     */
    if (dpp_instance.newoc && dpp_instance.newchan) {
        tlv->type = CHANGE_CHANNEL;
        tlv->length = 2;
        ptr = tlv->value;
        *ptr++ = dpp_instance.newoc;
        *ptr++ = dpp_instance.newchan;
        tlv = (TLV *)ptr;
    }

    /*
     * ...and now wrap the wrapped data
     */
    tlv->type = WRAPPED_DATA;
    tlv->length = AES_BLOCK_SIZE + wrapped_len;      /* IV || C */

    /*
     * put the cleartext attributes into ieee_order()
     */
    ptr = (unsigned char *)TLV_next(tlv);
    ieeeize_hton_attributes(attrs, (int)((unsigned char *)ptr - attrs));

    /*
     * setup DPP Action frame header to include as a component of AAD
     */
    setup_dpp_action_frame(peer, DPP_SUB_AUTH_REQUEST);
    siv_encrypt(&ctx, wrap, (TLV_value(tlv) + AES_BLOCK_SIZE),
                wrapped_len, TLV_value(tlv),
                2, peer->frame, sizeof(dpp_action_frame), attrs, ((unsigned char *)tlv - attrs));

    peer->bufferlen = (int)(ptr - peer->buffer);
    if (send_dpp_action_frame(peer)) {
        success = 1;
        peer->retrans = 0;
        peer->t0 = srv_add_timeout(srvctx, SRV_SEC(2), retransmit_auth, peer);
    }
    /*
     * and now that we've sent the DPP Auth Request, change channels if necessary
     */
    if (dpp_instance.newoc && dpp_instance.newchan) {
        if (change_dpp_channel(peer->handle, dpp_instance.newoc, dpp_instance.newchan) < 0) {
            dpp_debug(DPP_DEBUG_ERR, "can't change to operating class %d and channel %d!\n",
                      dpp_instance.newoc, dpp_instance.newchan);
            goto fin;
        }
    }
fin:
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
    if (!success) {
        EC_KEY_free(peer->my_proto);
    }
    if (M != NULL) {
        EC_POINT_free(M);
    }
    if (m1 != NULL) {
        free(m1);
    }
    return success;
}

//----------------------------------------------------------------------
// receiving routines for initiator and responder
//----------------------------------------------------------------------

static int
process_dpp_auth_confirm (struct candidate *peer, dpp_action_frame *frame, int framelen)
{
    unsigned char bootkeyhash[SHA256_DIGEST_LENGTH], *val;
    unsigned char initauth[SHA512_DIGEST_LENGTH], *attrs;
    TLV *tlv;
    int success = 0;
    siv_ctx ctx;

    attrs = frame->attributes;
    tlv = (TLV *)attrs;
    if ((TLV_type(tlv) != DPP_STATUS) || (TLV_length(tlv) != 1)) {
        dpp_debug(DPP_DEBUG_ERR, "status isn't first element in DPP Auth Confirm!\n");
        goto fin;
    }
    val = TLV_value(tlv);
    if (*val != STATUS_OK) {
        dpp_debug(DPP_DEBUG_ERR, "status in DPP Auth Confirm is not OK (%d)\n", *val);
        goto fin;
    }

    if (compute_bootstrap_key_hash(dpp_instance.bootstrap, bootkeyhash) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "unable to compute bootstrap hash to parse Auth Request\n");
        goto fin;
    }
    tlv = TLV_next(tlv);
    if ((TLV_type(tlv) != RESPONDER_BOOT_HASH) ||
        memcmp(TLV_value(tlv), bootkeyhash, SHA256_DIGEST_LENGTH)) {
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "Don't know the sender...bail for now!\n");
        goto fin;
    }

    if (peer->mauth) {
        if (compute_bootstrap_key_hash(peer->peer_bootstrap, bootkeyhash) < 1) {
            dpp_debug(DPP_DEBUG_ERR, "unable to compute bootstrap hash to parse Auth Response\n");
            goto fin;
        }

        tlv = TLV_next(tlv);
        if ((TLV_type(tlv) != INITIATOR_BOOT_HASH) ||
            memcmp(TLV_value(tlv), bootkeyhash, SHA256_DIGEST_LENGTH)) {
            dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "DPP Auth Resp is not for me!\n");
            goto fin;
        }
    } else {
        if (TLV_lookahead(tlv) == INITIATOR_BOOT_HASH) {
            dpp_debug(DPP_DEBUG_ERR, "not doing mutual authentication but initiator sent H(Bi)!\n");
            goto fin;
        }
    }
    
    tlv = TLV_next(tlv);
    if (TLV_type(tlv) != WRAPPED_DATA) {
        goto fin;
    }
    switch(dpp_instance.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_512);
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", dpp_instance.digestlen);
            goto fin;
    }
    if (siv_decrypt(&ctx, TLV_value(tlv) + AES_BLOCK_SIZE, TLV_value(tlv) + AES_BLOCK_SIZE,
                    TLV_length(tlv) - AES_BLOCK_SIZE, TLV_value(tlv), 
                    2, frame, sizeof(dpp_action_frame), attrs, (unsigned char *)tlv - attrs) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "can't decrypt auth tag in DPP Auth Confirm!\n");
        /*
         * TODO: silently fail
         */
        goto fin;
    }
    ieeeize_ntoh_attributes(TLV_value(tlv) + AES_BLOCK_SIZE, TLV_length(tlv) - AES_BLOCK_SIZE);
    tlv = (TLV *)(TLV_value(tlv) + AES_BLOCK_SIZE);

    dpp_debug(DPP_DEBUG_TRACE, "I-auth...\n");   // delete this
    if (generate_auth(peer, 1, initauth) != dpp_instance.digestlen) {
        dpp_debug(DPP_DEBUG_ERR, "can't generate initiator auth tag for DPP Auth Confirm\n");
        goto fin;
    }
    if (memcmp(initauth, TLV_value(tlv), dpp_instance.digestlen)) {
        dpp_debug(DPP_DEBUG_ERR, "initiator auth tag is wrong in DPP Auth Confirm!\n");
        goto fin;
    }
    debug_buffer(DPP_DEBUG_TRACE, "AUTHi'", initauth, dpp_instance.digestlen);
    
    dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "\nauthenticated initiator!\n");
    fflush(stdout);
    success = 1;
    
fin:
    return success;
}

static int
process_dpp_auth_response (struct candidate *peer, dpp_action_frame *frame, int framelen)
{
    int ret = -1, primarywraplen = 0, offset, len;
    unsigned char bootkeyhash[SHA256_DIGEST_LENGTH], *ptr, *val, *n1 = NULL;
    unsigned char respauth[SHA512_DIGEST_LENGTH], *attrs;
    EC_POINT *N = NULL, *L = NULL, *Pub = NULL;
    BIGNUM *x = NULL, *y = NULL, *n = NULL, *l = NULL;
    const BIGNUM *bi, *pi;
    const EC_POINT *Br;
    siv_ctx ctx;
    TLV *tlv;

    attrs = frame->attributes;
    len = framelen - sizeof(dpp_action_frame);
    if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
        ((n = BN_new()) == NULL) || ((N = EC_POINT_new(dpp_instance.group)) == NULL)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to create bignums to process DPP Auth Resp!\n");
        goto fin;
    }
   
    tlv = (TLV *)attrs;
    if ((TLV_type(tlv) != DPP_STATUS) || (TLV_length(tlv) != 1)) {
        dpp_debug(DPP_DEBUG_ERR, "no status in Auth Response, %d (%d bytes)\n",
                  TLV_type(tlv), TLV_length(tlv));
        goto fin;
    }
    val = TLV_value(tlv);
    if (*val != STATUS_OK) {
        dpp_debug(DPP_DEBUG_ERR, "status in DPP Auth Response is not OK (%d)\n", *val);
    }

    if (compute_bootstrap_key_hash(peer->peer_bootstrap, bootkeyhash) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "unable to compute bootstrap hash to parse Auth Response\n");
        goto fin;
    }
    tlv = TLV_next(tlv);
    if ((TLV_type(tlv) != RESPONDER_BOOT_HASH) ||
        memcmp(TLV_value(tlv), bootkeyhash, SHA256_DIGEST_LENGTH)) {
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "Don't know the sender...bail for now!\n");
        goto fin;
    }
    /*
     * we're the initiator, if a hash of our bootstrapping key is not there
     * then the responder doesn't want to do mutual authentication
     */
    if (TLV_lookahead(tlv) != INITIATOR_BOOT_HASH) {
        peer->mauth = 0;
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "not doing mutual authentication!\n");
    } else {
        /*
         * otherwise, he wants to do mutual authentication so make sure it's mine
         */
        if (compute_bootstrap_key_hash(dpp_instance.bootstrap, bootkeyhash) < 1) {
            dpp_debug(DPP_DEBUG_ERR, "unable to compute bootstrap hash to parse Auth Request\n");
            goto fin;
        }
        tlv = TLV_next(tlv);
        if (memcmp(TLV_value(tlv), bootkeyhash, SHA256_DIGEST_LENGTH)) {
            dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "DPP Auth Resp is not for me!\n");
            goto fin;
        }
        peer->mauth = 1;
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "doing mutual authentication!\n");
        /*
         * generate the variables we'll need for mutual authentication
         */
        if (((Pub = EC_POINT_new(dpp_instance.group)) == NULL) ||
            ((l = BN_new()) == NULL) || ((L = EC_POINT_new(dpp_instance.group)) == NULL)) {
            goto fin;
        }
    }

    /*
     * check DPP version (if v1, peer doesn't send attribute)
     */
    if ((tlv = find_tlv(PROTOCOL_VERSION, attrs, len)) != NULL) {
        if (peer->version != *((unsigned char *)TLV_value(tlv))) {
            dpp_debug(DPP_DEBUG_ERR, "version mismatch: we are %d, peer says %d\n",
                      peer->version, *((unsigned char *)TLV_value(tlv)));
            goto fin;
        }
    } else {
        if (peer->version > 1) {
            dpp_debug(DPP_DEBUG_ERR, "Peer did not include version in DPP Auth Response\n");
            goto fin;
        }
    }

    if (*val != STATUS_OK) {
        /*
         * status is bad so decrypt data wrapped with k1
         */
        switch(dpp_instance.digestlen) {
            case SHA256_DIGEST_LENGTH:
                siv_init(&ctx, peer->k1, SIV_256);
                break;
            case SHA384_DIGEST_LENGTH:
                siv_init(&ctx, peer->k1, SIV_384);
                break;
            case SHA512_DIGEST_LENGTH:
                siv_init(&ctx, peer->k1, SIV_512);
                break;
            default:
                dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", dpp_instance.digestlen);
                goto fin;
        }
        /*
         * find the wrapped data...
         */
        if ((tlv = find_tlv(WRAPPED_DATA, attrs, len)) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "unable to find primary wrapped data in DPP Auth Resp!\n");
            goto fin;
        }
        ptr = TLV_value(tlv) + AES_BLOCK_SIZE;
        primarywraplen = TLV_length(tlv) - AES_BLOCK_SIZE;
        /*
         * and unwrap it
         */
        if (siv_decrypt(&ctx, ptr, ptr, primarywraplen, TLV_value(tlv),
                        2, frame, sizeof(dpp_action_frame), attrs, ((unsigned char *)tlv - attrs)) < 1) {
            dpp_debug (DPP_DEBUG_ERR, "can't decrypt blob in DPP Auth Resp (status NOT OK)!\n");
            /*
             * so the status says fail and the blob can't be decrypted, this
             * looks like just a bad frame, ignore it.
             */
            goto fin;
        }
        /*
         * ieee-ize the unwrapped attributes
         */
        ieeeize_ntoh_attributes(ptr, primarywraplen);

        if ((tlv = find_tlv(RESPONDER_CAPABILITIES, ptr, primarywraplen)) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "can't find responder capabilities in primary wrapped data\n");
            goto fin;
        }
        if (*val == STATUS_RESPONSE_PENDING) {
            /*
             * give the guy 20s to get our bootstrapping key.... then destroy him.
             */
            peer->t0 = srv_add_timeout(srvctx, SRV_SEC(20), destroy_peer, peer);
            ret = 1;
            goto fin;
        } else {
            val = TLV_value(tlv);
            dpp_debug(DPP_DEBUG_TRACE, "incompatible responder role: %s (%x)\n", *val == DPP_CONFIGURATOR ? "configurator" : \
                      *val == DPP_ENROLLEE ? "enrollee" : *val == (DPP_CONFIGURATOR&DPP_ENROLLEE) ? "both" : "unknown", *val);

            fail_dpp_peer(peer);
            goto fin;
        }
    } 
    /*
     * status is OK so continue...
     */
    if ((tlv = find_tlv(RESPONDER_PROTOCOL_KEY, attrs, len)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to find responder protocol key in DPP Auth Resp!\n");
        goto fin;
    }
    BN_bin2bn(TLV_value(tlv), dpp_instance.primelen, x);
    BN_bin2bn(TLV_value(tlv) + dpp_instance.primelen, dpp_instance.primelen, y);

    if (!EC_POINT_set_affine_coordinates_GFp(dpp_instance.group, peer->peer_proto, x, y, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to affix peer's protocol key!\n");
        goto fin;
    }
    if (!EC_POINT_is_on_curve(dpp_instance.group, peer->peer_proto, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "responder's protocol key is invalid!\n");
        goto fin;
    }
    debug_ec_point(DPP_DEBUG_TRACE, "Pr", peer->peer_proto);

    /*
     *  N = pi * Pr
     */
    if (((pi = EC_KEY_get0_private_key(peer->my_proto)) == NULL) ||
        !EC_POINT_mul(dpp_instance.group, N, NULL, peer->peer_proto, pi, bnctx) ||
        !EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, N, n, NULL, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to compute N!\n");
        goto fin;
    }
    /*
     * compute k2
     */
    if ((n1 = (unsigned char *)malloc(dpp_instance.primelen)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to malloc data to compute k2\n");
        goto fin;
    }
    memset(n1, 0, dpp_instance.primelen);
    offset = dpp_instance.primelen - BN_num_bytes(n);
    BN_bn2bin(n, n1 + offset);
    hkdf(dpp_instance.hashfcn, 0, n1, dpp_instance.primelen, NULL, 0,
         (unsigned char *)"second intermediate key", strlen("second intermediate key"),
         peer->k2, dpp_instance.digestlen);

    debug_buffer(DPP_DEBUG_TRACE, "k2", peer->k2, dpp_instance.digestlen);

    switch(dpp_instance.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, peer->k2, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, peer->k2, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, peer->k2, SIV_512);
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", dpp_instance.digestlen);
            goto fin;
    }
    /*
     * find the wrapped data...
     */
    if ((tlv = find_tlv(WRAPPED_DATA, attrs, len)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to find primary wrapped data in DPP Auth Resp!\n");
        goto fin;
    }
    ptr = TLV_value(tlv) + AES_BLOCK_SIZE;
    primarywraplen = TLV_length(tlv) - AES_BLOCK_SIZE;
    /*
     * ...put the AAD back into ieee-order and unwrap it
     */
    ieeeize_hton_attributes(attrs, (int)(((unsigned char *)tlv - attrs)));
    if (siv_decrypt(&ctx, ptr, ptr, primarywraplen, TLV_value(tlv),
                    2, frame, sizeof(dpp_action_frame), attrs, ((unsigned char *)tlv - attrs)) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "can't decrypt primary blob in DPP Auth Resp!\n");
        /*
         * TODO: send dpp_auth_confirm with a status of STATUS_DECRYPT_FAILURE
         */
        goto fin;
    }
    ieeeize_ntoh_attributes(ptr, primarywraplen);

    if ((tlv = find_tlv(RESPONDER_NONCE, ptr, primarywraplen)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "can't find responder nonce in primary wrapped data\n");
        goto fin;
    }
    memcpy(peer->peernonce, TLV_value(tlv), TLV_length(tlv));

    debug_buffer(DPP_DEBUG_TRACE, "responder's nonce", peer->peernonce, TLV_length(tlv));
    
    if (((tlv = find_tlv(INITIATOR_NONCE, ptr, primarywraplen)) == NULL) ||
        memcmp(peer->mynonce, TLV_value(tlv), dpp_instance.noncelen)) {
        dpp_debug(DPP_DEBUG_ERR, "my nonce isn't in primary wrapped data\n");
        goto fin;
    }
    if ((tlv = find_tlv(RESPONDER_CAPABILITIES, ptr, primarywraplen)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "can't find responder capabilities in primary wrapped data\n");
        goto fin;
    }
    val = TLV_value(tlv);

    dpp_debug(DPP_DEBUG_TRACE, "responder role: %s\n", *val == DPP_CONFIGURATOR ? "configurator" : \
           *val == DPP_ENROLLEE ? "enrollee" : *val == (DPP_CONFIGURATOR&DPP_ENROLLEE) ? "both" : "unknown");

    /*
     * make sure the responder didn't choose badly
     */
    if (dpp_instance.core == *val) {
        dpp_debug(DPP_DEBUG_ERR, "incompatible capabilities!\n");
        goto fin;
    }
    /*
     * if the choice was not bad then we are the opposite of the choice
     */
    switch (*val) {
        case DPP_CONFIGURATOR:
            peer->core = DPP_ENROLLEE;
            break;
        case DPP_ENROLLEE:
            peer->core = DPP_CONFIGURATOR;
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "incompatible capabilities!\n");
            goto fin;
    }
    if (TLV_length(tlv) != 1) {
        dpp_debug(DPP_DEBUG_ERR, "responder capabilities are wrong size\n");
        goto fin;
    }
    dpp_debug(DPP_DEBUG_TRACE, "my role: %s\n", peer->core == DPP_CONFIGURATOR ? "configurator" : \
              peer->core == DPP_ENROLLEE ? "enrollee" : \
              peer->core == (DPP_CONFIGURATOR|DPP_ENROLLEE) ? "both" : "unknown");

    if ((tlv = find_tlv(WRAPPED_DATA, ptr, primarywraplen)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "can't find secondary wrapped data in DPP Auth Resp\n");
        goto fin;
    }

    if (peer->mauth) {
        /*
         * For the initiator, L = bi * (Br + Pr)
         */
        if (((bi = EC_KEY_get0_private_key(dpp_instance.bootstrap)) == NULL) ||
            ((Br = EC_KEY_get0_public_key(peer->peer_bootstrap)) == NULL) ||
            !EC_POINT_add(dpp_instance.group, Pub, Br, peer->peer_proto, bnctx) ||
            !EC_POINT_mul(dpp_instance.group, L, NULL, Pub, bi, bnctx) ||
            !EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, L, l, NULL, bnctx)) {
            dpp_debug(DPP_DEBUG_ERR, "unable to compute L!\n");
            goto fin;
        }

        if (!compute_ke(peer, n, l)) {
            dpp_debug(DPP_DEBUG_ERR, "unable to compute ke!\n");
            goto fin;
        }
    } else {
        if (!compute_ke(peer, n, NULL)) {
            dpp_debug(DPP_DEBUG_ERR, "unable to compute ke!\n");
            goto fin;
        }
    }
     
    debug_buffer(DPP_DEBUG_TRACE, "ke", peer->ke, dpp_instance.digestlen);
    
    switch(dpp_instance.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, peer->ke, SIV_512);
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", dpp_instance.digestlen);
            goto fin;
    }

    /*
     * no AAD on inner wrapped data, just unwrap it
     */
    if (siv_decrypt(&ctx, TLV_value(tlv) + AES_BLOCK_SIZE, TLV_value(tlv) + AES_BLOCK_SIZE,
                    TLV_length(tlv) - AES_BLOCK_SIZE, TLV_value(tlv), 0) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "can't decrypt secondary blob in DPP Auth Resp!\n");
        (void)send_dpp_auth_confirm(peer, STATUS_AUTH_FAILURE);
        goto fin;
    }
    ieeeize_ntoh_attributes(TLV_value(tlv) + AES_BLOCK_SIZE, TLV_length(tlv) - AES_BLOCK_SIZE);

    if ((tlv = find_tlv(RESPONDER_AUTH_TAG, TLV_value(tlv) + AES_BLOCK_SIZE,
                        TLV_length(tlv) - AES_BLOCK_SIZE)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "can't find responder auth tag in DPP Auth Resp!\n");
        goto fin;
    }
    dpp_debug(DPP_DEBUG_TRACE, "R-auth...\n");  // delete this
    if ((generate_auth(peer, 0, respauth) != dpp_instance.digestlen) ||
        memcmp(respauth, TLV_value(tlv), TLV_length(tlv))) {
        dpp_debug(DPP_DEBUG_ERR, "responder auth token is incorrect!\n");
        /*
         * TODO: send dpp_auth_confirm with a status of STATUS_AUTH_FAILURE
         */
        goto fin;
    }
    debug_buffer(DPP_DEBUG_TRACE, "AUTHr'", respauth, dpp_instance.digestlen);

    dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "authenticated responder!\n");
    
    ret = 1;

  fin:
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
    if (n != NULL) {
        BN_free(n);
    }
    if (l != NULL) {
        BN_free(l);
    }
    if (N != NULL) {
        EC_POINT_free(N);
    }
    if (L != NULL) {
        EC_POINT_free(L);
    }
    if (Pub != NULL) {
        EC_POINT_free(Pub);
    }
    if (n1 != NULL) {
        free(n1);
    }
    return ret;
}

static int
process_dpp_auth_request (struct candidate *peer, dpp_action_frame *frame, int framelen)
{
    unsigned char bootkeyhash[SHA256_DIGEST_LENGTH], *ptr, *m1 = NULL, *attrs;
    siv_ctx ctx;
    int ret = 0, offset, len;
    TLV *tlv;
    unsigned char opclass, channel;
    const BIGNUM *priv;
    EC_POINT *M = NULL;
    BIGNUM *x = NULL, *y = NULL;

    attrs = frame->attributes;
    len = framelen - sizeof(dpp_action_frame);
    if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
        ((M = EC_POINT_new(dpp_instance.group)) == NULL)) {
        dpp_debug(DPP_DEBUG_ERR, "can't malloc bignums!\n");
        goto fin;
    }

    tlv = (TLV *)attrs;
    if (TLV_type(tlv) != RESPONDER_BOOT_HASH) {
        dpp_debug(DPP_DEBUG_ERR, "responder boot hash isn't first element!\n");
        goto fin;
    }
    if (compute_bootstrap_key_hash(dpp_instance.bootstrap, bootkeyhash) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "unable to compute bootstrap hash to parse Auth Request\n");
        goto fin;
    }
    if (memcmp(TLV_value(tlv), bootkeyhash, SHA256_DIGEST_LENGTH)) {
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "DPP Auth Request is not for me!\n");
        goto fin;
    }
    tlv = TLV_next(tlv);
    if (TLV_type(tlv) != INITIATOR_BOOT_HASH) {
        dpp_debug(DPP_DEBUG_ERR, "initiator boot hash isn't first element!\n");
        goto fin;
    }
    if (peer->mauth) {
        if (peer->peer_bootstrap == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "set to mutual auth but no peer bootstrap key!\n");
            goto fin;
        }
        /*
         * if we're doing mutual authentication then make sure we have the initiator's key
         */
        if (compute_bootstrap_key_hash(peer->peer_bootstrap, bootkeyhash) < 1) {
            dpp_debug(DPP_DEBUG_ERR, "unable to compute bootstrap hash to parse Auth Request\n");
            goto fin;
        }
        if (memcmp(TLV_value(tlv), bootkeyhash, SHA256_DIGEST_LENGTH)) {
            dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "Don't know the sender...bail for now!\n");
            goto fin;
        }
    }

    /*
     * if the peer includes the version TLV then use that, otherwise assume v1
     */
    if ((tlv = find_tlv(PROTOCOL_VERSION, attrs, len)) != NULL) {
        peer->version = *((unsigned char *)TLV_value(tlv));
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "peer sent a version of %d\n", peer->version);
        /*
         * attempt the lowest instead of just bailing on this guy
         */
        if (peer->version == 0) {
            peer->version = 1;
        }
    } else {
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "peer did not send a version, assuming 1\n");
        peer->version = 1;
    }

    if ((tlv = find_tlv(INITIATOR_PROTOCOL_KEY, attrs, len)) == NULL) {
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "can't find initiator's protocol key in Auth Req!\n");
        goto fin;
    }
    ptr = TLV_value(tlv);
    BN_bin2bn(ptr, dpp_instance.primelen, x);
    ptr += dpp_instance.primelen;
    BN_bin2bn(ptr, dpp_instance.primelen, y);

    if (!EC_POINT_set_affine_coordinates_GFp(dpp_instance.group, peer->peer_proto, x, y, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to affix peer's protocol key!\n");
        goto fin;
    }
    if (!EC_POINT_is_on_curve(dpp_instance.group, peer->peer_proto, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "initiator's protocol key is invalid!\n");
        goto fin;
    }
    debug_ec_point(DPP_DEBUG_TRACE, "Pi'", peer->peer_proto);
    
    if ((priv = EC_KEY_get0_private_key(dpp_instance.bootstrap)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to get my own private key!\n");
        goto fin;
    }

    if (!EC_POINT_mul(dpp_instance.group, M, NULL, peer->peer_proto, priv, bnctx) ||
        !EC_POINT_get_affine_coordinates_GFp(dpp_instance.group, M, peer->m, NULL, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to compute intermediate key M\n");
        goto fin;
    }
    if ((m1 = (unsigned char *)malloc(dpp_instance.primelen)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to alloc m1 to process DPP Auth Req\n");
        goto fin;
    }
    memset(m1, 0, dpp_instance.primelen);
    offset = dpp_instance.primelen - BN_num_bytes(peer->m);
    BN_bn2bin(peer->m, m1 + offset);
    hkdf(dpp_instance.hashfcn, 0, m1, dpp_instance.primelen, NULL, 0,
         (unsigned char *)"first intermediate key", strlen("first intermediate key"),
         peer->k1, dpp_instance.digestlen);

    debug_buffer(DPP_DEBUG_TRACE, "k1", peer->k1, dpp_instance.digestlen);
    
    switch(dpp_instance.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, peer->k1, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, peer->k1, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, peer->k1, SIV_512);
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", dpp_instance.digestlen);
            goto fin;
    }
    if ((tlv = find_tlv(WRAPPED_DATA, attrs, len)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "can't find wrapped data in DPP Auth Request!\n");
        goto fin;
    }
    if (siv_decrypt(&ctx, (TLV_value(tlv) + AES_BLOCK_SIZE), (TLV_value(tlv) + AES_BLOCK_SIZE),
                    TLV_length(tlv) - AES_BLOCK_SIZE, TLV_value(tlv), 
                    2, frame, sizeof(dpp_action_frame), attrs, ((unsigned char *)tlv - attrs)) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "can't decrypt blob in DPP Auth Req!\n");
        /*
         * TODO: send dpp_auth_response with a status of STATUS_DECRYPT_FAILURE
         */
        goto fin;
    }
    ieeeize_ntoh_attributes(TLV_value(tlv) + AES_BLOCK_SIZE, TLV_length(tlv) - AES_BLOCK_SIZE);
    
    /*
     * there are TLVs inside the wrapped blob, right past the IV!
     */
    tlv = (TLV *)(TLV_value(tlv) + AES_BLOCK_SIZE);
    if (TLV_type(tlv) != INITIATOR_NONCE) {
        dpp_debug(DPP_DEBUG_ERR, "expecting initiator's nonce, got %d\n", TLV_type(tlv));
        goto fin;
    }
    
    memcpy(peer->peernonce, TLV_value(tlv), dpp_instance.noncelen);

    debug_buffer(DPP_DEBUG_TRACE, "initiator's nonce", peer->peernonce, dpp_instance.noncelen);

    tlv = TLV_next(tlv);
    if (TLV_type(tlv) != INITIATOR_CAPABILITIES) {
        dpp_debug(DPP_DEBUG_ERR, "expecting capabilities, got %d\n", TLV_type(tlv));
        goto fin;
    }
    ptr = TLV_value(tlv);
    dpp_debug(DPP_DEBUG_TRACE, "initiator role: %s\n", *ptr == DPP_CONFIGURATOR ? "configurator" : \
           *ptr == DPP_ENROLLEE ? "enrollee" : *ptr == (DPP_CONFIGURATOR|DPP_ENROLLEE) ? "both" : "unknown");
    /*
     * if capabilities aren't opposites...
     */
    if ((*ptr ^ dpp_instance.core) == 0) {
        /*
         * ...and we're not supporting both then we're not a match
         */
        if (dpp_instance.core != (DPP_CONFIGURATOR|DPP_ENROLLEE)) {
            peer->core = dpp_instance.core;
            dpp_debug(DPP_DEBUG_ERR, "incompatiable capabilities!\n");
            send_dpp_auth_response(peer, STATUS_NOT_COMPATIBLE);
            fail_dpp_peer(peer);
            goto fin;
        }
        /*
         * ...otherwise we're both willing to be both so let's be the enrollee
         */
        peer->core = DPP_ENROLLEE;
    } else {
        /*
         * otherwise, we already support opposites
         */
        if (dpp_instance.core == (DPP_CONFIGURATOR|DPP_ENROLLEE)) {
            peer->core = (*ptr ^ dpp_instance.core);
        } else {
            peer->core = dpp_instance.core;
        }
        
    }
    dpp_debug(DPP_DEBUG_TRACE, "my role: %s\n", peer->core == DPP_CONFIGURATOR ? "configurator" : \
           peer->core == DPP_ENROLLEE ? "enrollee" : "unknown");

    /*
     * so the entire request looks good, see if the initiator wants a response
     * on a different channel
     */
    if ((tlv = find_tlv(CHANGE_CHANNEL, attrs, len)) != NULL) {
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "initiator wants to change channels!\n");
        ptr = TLV_value(tlv);
        opclass = *ptr;
        ptr++;
        channel = *ptr;
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "initiator wants to change channels to %d, %d!\n",
                  opclass, channel);
        if (change_dpp_channel(peer->handle, opclass, channel) < 0) {
            dpp_debug(DPP_DEBUG_ERR, "can't change to operating class %d and channel %d!\n",
                      opclass, channel);
            goto fin;
        }
    }

    ret = 1;
fin:
    if (m1 != NULL) {
        free(m1);
    }
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
    if (M != NULL) {
        EC_POINT_free(M);
    }
    return ret;
}

int
process_dpp_auth_frame (unsigned char *data, int len, dpp_handle handle)
{
    dpp_action_frame *frame = (dpp_action_frame *)data;
    struct candidate *peer = NULL;

    dpp_debug(DPP_DEBUG_TRACE, "enter process_dpp_auth_frame() for peer %d\n", handle);
    TAILQ_FOREACH(peer, &dpp_instance.peers, entry) {
        dpp_debug(DPP_DEBUG_TRACE, "\tpeer %d is in state %s\n", handle,
                  state_to_string(peer->state));
    }
    TAILQ_FOREACH(peer, &dpp_instance.peers, entry) {
        if (peer->handle == handle) {
            break;
        }
    }
    if (peer == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to find peer to do dpp!\n");
        return -1;
    }
    /*
     * make sure it's a DPP Authentication frame...
     */
    if ((memcmp(frame->oui_type, wfa_dpp, sizeof(wfa_dpp))) && (frame->cipher_suite == 1)) {
        dpp_debug(DPP_DEBUG_ERR, "got an action frame, not a dpp auth frame from\n");
        return -1;
    }
    /*
     * we found a peer, and it's a DPP frame! Cancel any timer we have set.
     */
    srv_rem_timeout(srvctx, peer->t0);

    /*
     * fix up the lengths of all the TLVs...
     */
    ieeeize_ntoh_attributes(frame->attributes, len - sizeof(dpp_action_frame));

    if (debug & DPP_DEBUG_TRACE) {
        dpp_debug(DPP_DEBUG_TRACE, "Got a DPP Auth Frame! In state %s\n",
                  state_to_string(peer->state));
        dump_tlvs(frame->attributes, len - sizeof(dpp_action_frame));
    }
    
    /*
     * implement the state machine for DPP
     */
    if (peer->is_initiator) {
        /*
         * initiator state machine
         */
        switch (peer->state) {
            case DPP_NOTHING:
                peer->state = DPP_BOOTSTRAPPED;
                /* fall-thru intentional */
            case DPP_BOOTSTRAPPED:
                break;
            case DPP_AUTHENTICATING:
                if (frame->frame_type != DPP_SUB_AUTH_RESPONSE) {
                    dpp_debug(DPP_DEBUG_ERR, "Initiator in AUTHENTICATING did not get DPP Auth Response!\n");
                    peer->t0 = srv_add_timeout(srvctx, SRV_SEC(2), retransmit_auth, peer);
                    break;
                }
                dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "initiator received DPP Auth Respond\n");
                if (process_dpp_auth_response(peer, frame, len) < 1) {
                    dpp_debug(DPP_DEBUG_ERR, "failed processing of DPP Auth Resp frame!\n");
                    return -1;
                }
                if (send_dpp_auth_confirm(peer, STATUS_OK) > 0) {
                    peer->state = DPP_AUTHENTICATED;
                }
                break;
            case DPP_AUTHENTICATED:
                dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "got a DPP Auth frame while already authenticated!\n");
                break;
            default:
                dpp_debug(DPP_DEBUG_ERR, "unknown state for peer!\n");
                return -1;
        }
    } else {
        /*
         * responder state machine
         */
        switch (peer->state) {
            case DPP_NOTHING:
            case DPP_BOOTSTRAPPED:
                /* fall-thru intentional */
            case DPP_AWAITING:
                /*
                 * the responder is awaiting the DPP Auth Init frame
                 */
                if (frame->frame_type != DPP_SUB_AUTH_REQUEST) {
                    dpp_debug(DPP_DEBUG_ERR, "Responder in AWAITING did not get DPP Auth Request!\n");
                    break;
                }
                dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "responder received DPP Auth Request\n");
                if (process_dpp_auth_request(peer, frame, len) < 1) {
                    dpp_debug(DPP_DEBUG_ERR, "failed processing of DPP Auth Request frame!\n");
                    return -1;
                }
                if (send_dpp_auth_response(peer, STATUS_OK) > 0) {
                    peer->state = DPP_AUTHENTICATING;
                } else {
                    dpp_debug(DPP_DEBUG_ERR, "send_dpp_auth_response() failed!\n");
                }
                break;
            case DPP_AUTHENTICATING:
                if (frame->frame_type != DPP_SUB_AUTH_CONFIRM) {
                    dpp_debug(DPP_DEBUG_ERR, "Responder in AUTHENTICATING did not get DPP Auth Confirm!\n");
                    peer->t0 = srv_add_timeout(srvctx, SRV_SEC(2), retransmit_auth, peer);
                    break;
                }
                dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "responder received DPP Auth Confirm\n");
                if (process_dpp_auth_confirm(peer, frame, len) < 1) {
                    dpp_debug(DPP_DEBUG_ERR, "failed processing of DPP Auth Confirm frame!\n");
                    return -1;
                }
                peer->state = DPP_AUTHENTICATED;
                break;
            case DPP_AUTHENTICATED:
                dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "got a DPP Auth frame while already authenticated!\n");
                break;
            default:
                dpp_debug(DPP_DEBUG_ERR, "unknown DPP Auth state for peer!\n");
                return -1;
        }
    }
    if (peer->state == DPP_AUTHENTICATED) {
        if (peer->core == DPP_ENROLLEE) {
            dpp_debug(DPP_DEBUG_ANY, "start the configuration protocol....\n");
            peer->t0 = srv_add_timeout(srvctx, SRV_MSEC(200), start_config_protocol, peer);
        } else {
            dpp_debug(DPP_DEBUG_ANY, "wait for the enrollee to start the configuration protocol....\n");
            peer->t0 = srv_add_timeout(srvctx, SRV_SEC(10), no_peer, peer);
        }
    }
    dpp_debug(DPP_DEBUG_TRACE, "exit process_dpp_auth_frame() for peer %d\n", handle);
    TAILQ_FOREACH(peer, &dpp_instance.peers, entry) {
        dpp_debug(DPP_DEBUG_TRACE, "\tpeer %d is in state %s\n", handle,
                  state_to_string(peer->state));
    }

    return 1;
}

static void
init_dpp_auth (timerid id, void *data)
{
    struct candidate *peer = (struct candidate *)data;

    dpp_debug(DPP_DEBUG_TRACE, "initiate DPP version %d\n", peer->version);
    if (send_dpp_auth_request(peer) > 0) {
        peer->state = DPP_AUTHENTICATING;
    }
    return;
}

dpp_handle
dpp_create_peer (char *keyb64, int initiator, int mutualauth, int mtu)
{
    struct candidate *peer;
    const BIGNUM *priv;
    int asn1len;
    const unsigned char *kptr;
    unsigned char keyasn1[1024];

    if (!dpp_initialized) {
        return -1;
    }
    
    if ((peer = (struct candidate *)malloc(sizeof(struct candidate))) == NULL) {
        return -1;
    }
    if ((peer->peer_proto = EC_POINT_new(dpp_instance.group)) == NULL) {
        free(peer);
        return -1;
    }
    if ((peer->m = BN_new()) == NULL) {
        EC_POINT_free(peer->peer_proto);
        free(peer);
        return -1;
    }
    peer->t0 = 0;
    peer->my_proto = NULL;
    peer->peernewproto = NULL;
    peer->mynewproto = NULL;
    peer->peer_bootstrap = NULL;
    peer->mauth = initiator ? 1 : mutualauth;   /* initiator changes, responder set */
    peer->csrattrs = NULL;
    peer->csrattrs_len = 0;

    if (mtu) {
        if (mtu > 8192) {
            dpp_debug(DPP_DEBUG_ANY, "cannot have an MTU of %d\n", mtu);
            free(peer);
            return -1;
        }
        peer->mtu = mtu - sizeof(struct ieee80211_mgmt_frame);
    } else {
        peer->mtu = 8192;
    }
    if ((peer->frame = malloc(peer->mtu)) == NULL) {
        free(peer);
        return -1;
    }

    peer->is_initiator = initiator;
    if (peer->is_initiator) {
        peer->version = 3;              /* we can do v3 now, so state it up front */
    } else {
        peer->version = 1;              /* leave it up to the initiator, assume the worst */
    }
    RAND_bytes(peer->enonce, dpp_instance.noncelen);
    dpp_debug(DPP_DEBUG_TRACE, "we %s the initiator, version is %d\n",
              peer->is_initiator ? "are" : "are not", peer->version);
    
    priv = EC_KEY_get0_private_key(dpp_instance.bootstrap);
    debug_a_bignum(DPP_DEBUG_TRACE, "my private bootstrap key", (BIGNUM *)priv);
    debug_ec_key(DPP_DEBUG_TRACE, "my public bootstrap key", dpp_instance.bootstrap);
    debug_asn1_ec(DPP_DEBUG_TRACE, "DER encoded ASN.1", dpp_instance.bootstrap, 0);

    if (keyb64 != NULL) { 
        /*
         * so get the peer's bootstrap key
         */
        if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)keyb64, strlen(keyb64))) < 0) {
            dpp_debug(DPP_DEBUG_ERR, "unable to decode bootstrap key\n");
            EC_POINT_free(peer->peer_proto);
            free(peer);
            return -1;
        }
        kptr = keyasn1;
        peer->peer_bootstrap = d2i_EC_PUBKEY(NULL, &kptr, asn1len);
    
        EC_KEY_set_conv_form(peer->peer_bootstrap, POINT_CONVERSION_COMPRESSED);
        EC_KEY_set_asn1_flag(peer->peer_bootstrap, OPENSSL_EC_NAMED_CURVE);
        debug_ec_key(DPP_DEBUG_TRACE, "peer's bootstrap key", peer->peer_bootstrap);
        debug_asn1_ec(DPP_DEBUG_TRACE, "DER encoded ASN.1", peer->peer_bootstrap, 0);
    } else if (peer->is_initiator) {
        dpp_debug(DPP_DEBUG_ERR, "Initiator needs responder's bootstrapping key!\n");
        EC_POINT_free(peer->peer_proto);
        free(peer);
        return -1;
    } 
    
    configurator_signkey = NULL;  // even if this is a configurator, used by discovery
    connector = NULL;
    connector_len = 0;
    peer->state = DPP_BOOTSTRAPPED;
    TAILQ_INSERT_HEAD(&dpp_instance.peers, peer, entry);

    peer->handle = ++next_handle; // safe to assume we won't have 2^32 active sessions

    dpp_debug(DPP_DEBUG_TRACE, "\n------- Start of DPP Authentication Protocol ---------\n");
    if (peer->is_initiator) {
        peer->t0 = srv_add_timeout(srvctx, SRV_MSEC(200), init_dpp_auth, peer);
    } else if (do_chirp) {
        struct chirpdest *chirpto;

        dpp_debug(DPP_DEBUG_TRACE, "chirp list:\n");
        TAILQ_FOREACH(chirpto, &chirpdests, entry) {
            dpp_debug(DPP_DEBUG_TRACE, "\t%ld\n", chirpto->freq);
        }
        dpp_debug(DPP_DEBUG_TRACE, "start chirping...\n");
        peer->t0 = srv_add_timeout(srvctx, SRV_MSEC(500), start_dpp_chirp, peer);
    }
    
    return peer->handle;
}

void
dpp_free_peer (dpp_handle handle)
{
    struct candidate *peer = NULL;

    TAILQ_FOREACH(peer, &dpp_instance.peers, entry) {
        if (peer->handle == handle) {
            break;
        }
    }
    if (peer == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "no peer found with handle %d\n", handle);
        return;
    }
    /*
     * no need to add a timeout, just destroy it
     */
    destroy_peer(0, peer);
    return;
}

void
dpp_add_chirp_freq (unsigned char *bssid, unsigned long freq)
{
    struct chirpdest *chirpto;

    /*
     * see if this frequency is already on the list
     */
    TAILQ_FOREACH(chirpto, &chirpdests, entry) {
        if (chirpto->freq == freq) {
            return;
        }
    }
    if ((chirpto = (struct chirpdest *)malloc(sizeof(struct chirpdest))) == NULL) {
        return;
    }
    memcpy(chirpto->bssid, bssid, ETH_ALEN);
    chirpto->freq = freq;
    TAILQ_INSERT_TAIL(&chirpdests, chirpto, entry);
    return;
}

static void
addpolicy (char *akm, char *auxdata, char *ssid)
{
    struct cpolicy *cp;

    if ((cp = (struct cpolicy *)malloc(sizeof(struct cpolicy))) == NULL) {
        return;
    }
    strcpy(cp->akm, akm);
    strcpy(cp->auxdata, auxdata);
    strcpy(cp->ssid, ssid);
    TAILQ_INSERT_TAIL(&cpolicies, cp, entry);
    return;
}

int
dpp_initialize (int core, char *keyfile, char *signkeyfile, int newgrp,
                char *enrolleerole, char *mudurl, int chirp, char *caip,
                int opclass, int channel, int verbosity)
{
    FILE *fp;
    BIO *bio = NULL;
    int ret = 0;
    struct cpolicy cp, *pol;

    /*
     * initialize globals 
     */
    dpp_initialized = 1;
    if ((bnctx = BN_CTX_new()) == NULL) {
        fprintf(stderr, "cannot create bignum context!\n");
        return -1;
    }
    /*
     * set defaults and read in config
     */
    debug = verbosity;
    TAILQ_INIT(&chirpdests);
    TAILQ_INIT(&cpolicies);
    do_chirp = chirp;

    if (!core) {                /* have to chose one! */
        return -1;
    }
    memset(dpp_instance.mudurl, 0, sizeof(dpp_instance.mudurl));
    dpp_instance.core = core;
    switch (core) {
        case DPP_ENROLLEE:
            dpp_debug(DPP_DEBUG_TRACE, "role: enrollee\n");
            break;
        case DPP_CONFIGURATOR:
            dpp_debug(DPP_DEBUG_TRACE, "role: configurator\n");
            break;
        case (DPP_ENROLLEE | DPP_CONFIGURATOR):
            dpp_debug(DPP_DEBUG_TRACE, "role: both enrollee and configurator\n");
            break;
        default:
            dpp_debug(DPP_DEBUG_TRACE, "role: unknown... %x\n", core);
    }

    /*
     * if we're the configurator get the signing key...
     */
    dpp_instance.newgroup = 0;
    if (core & DPP_CONFIGURATOR) {
        bio = BIO_new(BIO_s_file());
        if ((fp = fopen(signkeyfile, "r")) == NULL) {
            fprintf(stderr, "DPP: unable to open keyfile %s\n", signkeyfile);
            ret = -1;
            goto fin;
        }
        BIO_set_fp(bio, fp, BIO_CLOSE);
        if ((dpp_instance.signkey = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL)) == NULL) {
            fprintf(stderr, "DPP: unable to read key in keyfile %s\n", signkeyfile);
            ret = -1;
            goto fin;
        }
        BIO_free(bio);

        if ((fp = fopen("configakm", "r")) != NULL) {
            while (!feof(fp)) {
                if (fscanf(fp, "%s %s %s", cp.akm, cp.auxdata, cp.ssid) < 1) {
                    fclose(fp);
                    break;
                }
                addpolicy(cp.akm, cp.auxdata, cp.ssid);
            }
        }
        /*
         * if there are no policies just make one up for testing purposes
         */
        if (TAILQ_EMPTY(&cpolicies)) {
            addpolicy("dpp", "<none>", "goaway");
        }
        TAILQ_FOREACH(pol, &cpolicies, entry) {
            if (strstr(pol->akm, "dot1x") != NULL) {
                dpp_instance.enterprise = 1;
            }
            dpp_debug(DPP_DEBUG_TRACE, "AKM: %s, auxdata: %s, SSID: %s\n",
                   pol->akm, pol->auxdata, pol->ssid);
        }
        dpp_instance.newgroup = newgrp;
    } else {
        strcpy(dpp_instance.enrollee_role, enrolleerole);
        if (mudurl) {
            strcpy(dpp_instance.mudurl, mudurl);
        }
    }

    dpp_instance.cacert = NULL;
    if (dpp_instance.enterprise) {
        if ((dpp_instance.cacert_len = get_cacerts(&dpp_instance.cacert, caip)) < 0) {
            dpp_debug(DPP_DEBUG_ERR, "can't talk to CA!\n");
            dpp_debug(DPP_DEBUG_ERR, "turning off enterprise for DPP\n");
            dpp_instance.enterprise = 0;
        } else {
            strcpy(dpp_instance.caip, caip);
            dpp_debug(DPP_DEBUG_TRACE, "got a %d byte cert from CA at %s\n",
                      dpp_instance.cacert_len, caip);
        }
    }

    dpp_instance.newoc = opclass;
    dpp_instance.newchan = channel;
    
    dpp_instance.group_num = 0;
    if ((fp = fopen(keyfile, "r")) == NULL) {
        fprintf(stderr, "DPP: unable to open keyfile %s\n", keyfile);
        return -1;
    }
    bio = BIO_new(BIO_s_file());
    BIO_set_fp(bio, fp, BIO_CLOSE);
    if ((dpp_instance.bootstrap = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL)) == NULL) {
        fprintf(stderr, "DPP: unable to read key in keyfile %s\n", keyfile);
        ret = -1;
        goto fin;
    }
    BIO_free(bio);
    EC_KEY_set_conv_form(dpp_instance.bootstrap, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(dpp_instance.bootstrap, OPENSSL_EC_NAMED_CURVE);

    if ((dpp_instance.group = EC_KEY_get0_group(dpp_instance.bootstrap)) == NULL) {
        fprintf(stderr, "DPP: unable to get group of bootstrap key!\n");
        ret = -1;
        goto fin;
    }
    dpp_instance.nid = EC_GROUP_get_curve_name(dpp_instance.group);
    switch (dpp_instance.nid) {
        case NID_X9_62_prime256v1:
            dpp_instance.group_num = 19;
            dpp_instance.hashfcn = EVP_sha256();
            dpp_instance.digestlen = 32;
            break;
        case NID_secp384r1:
            dpp_instance.group_num = 20;
            dpp_instance.hashfcn = EVP_sha384();
            dpp_instance.digestlen = 48;
            break;
        case NID_secp521r1:
            dpp_instance.group_num = 21;
            dpp_instance.hashfcn = EVP_sha512();
            dpp_instance.digestlen = 64;
            break;
        case NID_X9_62_prime192v1:
            dpp_instance.group_num = 25;
            dpp_instance.hashfcn = EVP_sha256();
            dpp_instance.digestlen = 32;
            break;
        case NID_secp224r1:
            dpp_instance.group_num = 26;
            dpp_instance.hashfcn = EVP_sha256();
            dpp_instance.digestlen = 32;
            break;
#ifdef HAS_BRAINPOOL
        case NID_brainpoolP256r1:
            dpp_instance.group_num = 28;
            dpp_instance.hashfcn = EVP_sha256();
            dpp_instance.digestlen = 32;
            break;
        case NID_brainpoolP384r1:
            dpp_instance.group_num = 29;
            dpp_instance.hashfcn = EVP_sha384();
            dpp_instance.digestlen = 48;
            break;
        case NID_brainpoolP512r1:
            dpp_instance.group_num = 30;
            dpp_instance.hashfcn = EVP_sha512();
            dpp_instance.digestlen = 64;
            break;
#endif  /* HAS_BRAINPOOL */
        default:
            dpp_debug(DPP_DEBUG_ERR, "bootstrap key from unknown group!\n");
            ret = -1;
            goto fin;
    }

    dpp_instance.primelen = prime_len_by_curve(dpp_instance.group_num);

    /*
     * if we're the configurator and were initialized to ask for a new key
     * make sure it differs from our bootstrapping key, if not don't ask
     */
    if (dpp_instance.newgroup) {
        if (dpp_instance.group_num == dpp_instance.newgroup) {
            dpp_instance.newgroup = 0;
        } else {
            /*
             * if we are gonna ask, then generate a keypair on the new curve
             */
            if ((dpp_instance.Pc = generate_new_protocol_key(dpp_instance.newgroup)) == NULL) {
                dpp_debug(DPP_DEBUG_CRYPTO, "unable to create new protocol key in group %d\n",
                          dpp_instance.newgroup);
                dpp_instance.newgroup = 0;
            }
        }
    }             
    dpp_instance.noncelen = dpp_instance.digestlen/2;
    EVP_add_digest(dpp_instance.hashfcn);
    if (dpp_instance.hashfcn != EVP_sha256()) {
        EVP_add_digest(EVP_sha256());   /* to hash bootstrapping keys */
    }
    TAILQ_INIT(&dpp_instance.peers);
    ret = 1;
fin:
    return ret;
}


