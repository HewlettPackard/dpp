/*
 * (c) Copyright 2016, 2017, 2018 Hewlett Packard Enterprise Development LP
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
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "ieee802_11.h"
#include "aes_siv.h"
#include "service.h"
#include "tlv.h"
#include "hkdf.h"
#include "os_glue.h"
#include "utils.h"
#ifdef FREEBSD
#include "helpers.h"
#endif  /* FREEBSD */

/*
 * DPP debugging bitmask
 */
#define DPP_DEBUG_ERR           0x01
#define DPP_DEBUG_PROTOCOL_MSG  0x02
#define DPP_DEBUG_STATE_MACHINE 0x04
#define DPP_DEBUG_CRYPTO        0x08
#define DPP_DEBUG_CRYPTO_VERB   0x10
#define DPP_DEBUG_TRACE         0x20
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

struct candidate {
    TAILQ_ENTRY(candidate) entry;
    dpp_handle handle;

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
    unsigned short state;
    BIGNUM *m;
    unsigned char core;                 /* configurator or enrollee for this time */
    int mauth;                          /* mutual authentication (1) or not (0) */
    unsigned char k1[SHA512_DIGEST_LENGTH];
    unsigned char k2[SHA512_DIGEST_LENGTH];
    unsigned char ke[SHA512_DIGEST_LENGTH];
    unsigned char peernonce[SHA512_DIGEST_LENGTH/2];
    unsigned char mynonce[SHA512_DIGEST_LENGTH/2];
    unsigned char buffer[4096];         /* can be fragmented during config exchange */
    int bufferlen;
    unsigned char retrans;
#define WIRELESS_MTU    1300            /* play with fragmentation */
    unsigned char frame[WIRELESS_MTU + 40];
    int framelen;
    /*
     * dpp config stuff
     */
    int nextfragment;
    char enrollee_name[80];
    char enrollee_role[10];
    char *connector;
    int connector_len;
    char discovery_transaction;
    EC_KEY *configurator_signkey;
    unsigned char csign_kid[KID_LENGTH];
    unsigned char field;
    unsigned char enonce[SHA512_DIGEST_LENGTH/2];
};

/*
 * our instance of DPP
 */
struct _dpp_instance {
    TAILQ_HEAD(blah, candidate) peers;
    EC_KEY *bootstrap;
    EC_KEY *signkey;
    const EC_GROUP *group;
    const EVP_MD *hashfcn;
    char core;                  /* capabile of being configurator or enrollee */
    char newoc;                 /* switch to this new operating class after sending DDP Auth Req */
    char newchan;               /* swithc to this new channel after sending DPP Auth Req */
    char enrollee_role[10];     /* role for an enrollee */
    int mauth;                  /* mutual authentication (1) or not (0) */
    int group_num;              /* these are handy to keep around */
    int primelen;               /* and not have to continually */
    int digestlen;              /* compute them from "bootstrap" */
    int noncelen;
    int nid;                    /* ditto */
} dpp_instance;

/*
 * global variables
 */
extern service_context srvctx;

static dpp_handle next_handle = 0;
static int dpp_initialized = 0;
static BN_CTX *bnctx = NULL;
static int debug = 0;
static int is_initiator;
static unsigned char trans_id = 0;

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
    BIO *bio, *bout;

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

#if 0
static void
dump_tlvs (unsigned char *attributes, int len)
{
    unsigned char *ptr = attributes;
    TLV *tlv;

    while (ptr < (attributes + len)) {
        tlv = (TLV *)ptr;
        ptr = (unsigned char *)TLV_next(tlv);
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "type %d, length %d, ", TLV_type(tlv), TLV_length(tlv));
        print_buffer("value", TLV_value(tlv), TLV_length(tlv));
    }
}
#endif

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

//----------------------------------------------------------------------
// routines common between initiator and responder
//----------------------------------------------------------------------

static void
destroy_peer (timerid id, void *data)
{
    struct candidate *peer = (struct candidate *)data;

    srv_rem_timeout(srvctx, peer->t0);
    if (peer->my_proto != NULL) {
        EC_KEY_free(peer->my_proto);
    }
    EC_POINT_clear_free(peer->peer_proto);
    EC_KEY_free(peer->peer_bootstrap);
    BN_free(peer->m);
    /*
     * zero out our secrets and other goo
     */
    memset(peer->k1, 0, SHA512_DIGEST_LENGTH);
    memset(peer->k2, 0, SHA512_DIGEST_LENGTH);
    memset(peer->ke, 0, SHA512_DIGEST_LENGTH);
    memset(peer->peernonce, 0, SHA512_DIGEST_LENGTH/2);
    memset(peer->mynonce, 0, SHA512_DIGEST_LENGTH/2);
    memset(peer->buffer, 0, 2048);
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
    (void)srv_add_timeout(srvctx, SRV_MSEC(1), destroy_peer, peer);
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
    } else if (transmit_config_frame(peer->handle, peer->field, peer->frame, peer->framelen)) {
        dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "retransmitting...for the %d time\n", peer->retrans);
        peer->t0 = srv_add_timeout(srvctx, SRV_SEC(2), retransmit_config, peer);
        peer->retrans++;
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
            if (peer->bufferlen > WIRELESS_MTU) {
                /*
                 * fill in the generic header goo
                 */
                garesp = (gas_action_resp_frame *)peer->frame;
                garesp->dialog_token = peer->dialog_token;
                peer->nextfragment = 0;         // where we start fragmenting... the beginning!
                memcpy(garesp->ad_proto_elem, dpp_proto_elem_resp, sizeof(dpp_proto_elem_resp));
                memcpy(garesp->ad_proto_id, dpp_proto_id, sizeof(dpp_proto_id));
                /*
                 * comback delay of 1 indicates fragmentation and we send back a 0 length response
                 */
                garesp->status_code = 0;       // success!
                garesp->comeback_delay = 1;
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
            gacresp->comeback_delay = 0;
            /*
             * fill in the fragment number (+1 because it starts at 1 and nextfrag starts at 0)
             * record how big the next chunk will be
             */
            gacresp->fragment_id = peer->nextfragment/WIRELESS_MTU;
            if ((peer->bufferlen - peer->nextfragment) > WIRELESS_MTU) {
                gacresp->query_resplen = WIRELESS_MTU;
                gacresp->fragment_id |= 0x80;   // more fragments!
            } else {
                gacresp->query_resplen = peer->bufferlen - peer->nextfragment;
            }
            memcpy(gacresp->query_resp, peer->buffer + peer->nextfragment, gacresp->query_resplen);
            peer->nextfragment += gacresp->query_resplen;
            peer->field = field;
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
    dpp_debug(DPP_DEBUG_TRACE, "sending a %s dpp config frame\n", 
              field == GAS_INITIAL_REQUEST ? "GAS_INITIAL_REQUEST" : \
              field == GAS_INITIAL_RESPONSE ? "GAS_INITIAL_RESPONSE" : \
              field == GAS_COMEBACK_REQUEST ? "GAS_COMEBACK_REQUEST" : \
              field == GAS_COMEBACK_RESPONSE ? "GAS_COMEBACK_RESPONSE" : "unknown");
    ret = transmit_config_frame(peer->handle, field, peer->frame, peer->framelen);
    return ret;
}

static void
setup_dpp_auth_frame (struct candidate *peer, unsigned char frametype)
{
    dpp_action_frame *frame;

    frame = (dpp_action_frame *)peer->frame;
    memcpy(frame->oui_type, wfa_dpp, sizeof(wfa_dpp));
    frame->cipher_suite = 1;
    frame->frame_type = frametype;

    return;
}

static int
send_dpp_auth_frame (struct candidate *peer)
{
    dpp_action_frame *frame;

    frame = (dpp_action_frame *)peer->frame;
    memcpy(frame->attributes, peer->buffer, peer->bufferlen);
    return transmit_auth_frame(peer->handle, peer->frame, peer->bufferlen + sizeof(dpp_action_frame));
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

static void
ieee_ize_attributes (unsigned char *attributes, int len)
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

//----------------------------------------------------------------------
// DPP discovery exchange routines
//----------------------------------------------------------------------

static int
send_dpp_discovery_frame (struct candidate *peer, unsigned char frametype, unsigned char tid)
{
    TLV *tlv;
    dpp_action_frame *frame;

    memset(peer->buffer, 0, sizeof(peer->buffer));

    tlv = (TLV *)peer->buffer;
    tlv = TLV_set_tlv(tlv, TRANSACTION_IDENTIFIER, 1, &tid);
    tlv = TLV_set_tlv(tlv, CONNECTOR, peer->connector_len, (unsigned char *)peer->connector);
    peer->bufferlen = (int)((unsigned char *)tlv - peer->buffer);

    ieee_ize_attributes(peer->buffer, peer->bufferlen);

    frame = (dpp_action_frame *)peer->frame;
    memcpy(frame->oui_type, wfa_dpp, sizeof(wfa_dpp));
    frame->cipher_suite = 1;
    frame->frame_type = frametype;
    memcpy(frame->attributes, peer->buffer, peer->bufferlen);
    /*
     * TODO: retransmission....
     */
    return transmit_discovery_frame(peer->handle, peer->frame, peer->bufferlen + sizeof(dpp_action_frame));
}

int
dpp_begin_discovery (dpp_handle handle)
{
    struct candidate *peer = NULL;

    dpp_debug(DPP_DEBUG_TRACE, "initiate DPP discovery...\n");

    TAILQ_FOREACH(peer, &dpp_instance.peers, entry) {
        if (peer->handle == handle) {
            break;
        }
    }
    if (peer == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "don't have state to initiate DPP!\n");
        return -1;
    }
    if ((peer->connector == NULL) || (peer->connector_len < 1)) {
        dpp_debug(DPP_DEBUG_ERR, "don't have a connector for peer with handle %d\n", handle);
        return -1;
    }

    trans_id++;
    peer->discovery_transaction = trans_id;
    send_dpp_discovery_frame (peer, DPP_SUB_PEER_DISCOVER_REQ, trans_id);
    
    return 1;
}

static int
process_dpp_discovery_connector (struct candidate *peer, unsigned char *connector, int connector_len)
{
    unsigned char unburl[1024], *dot, pmk[SHA512_DIGEST_LENGTH], pmkid[SHA512_DIGEST_LENGTH], *nx = NULL;
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
    dot = (unsigned char *)strstr((char *)connector, ".");
    if ((unburllen = base64urldecode(unburl, connector, dot - connector)) < 1) {
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
    if (((int)(estr - sstr) != KID_LENGTH) || memcmp(peer->csign_kid, sstr, KID_LENGTH)) {
        dpp_debug(DPP_DEBUG_ERR, "'kid' in peer's connector unknown!\n");
        debug_buffer(DPP_DEBUG_ERR, "configurator's 'kid'",
                     (unsigned char *)peer->csign_kid, KID_LENGTH);
        debug_buffer(DPP_DEBUG_ERR, "'kid' in peer's connector",
                     (unsigned char *)sstr, (int)(estr - sstr));
        return -1;
    }
    dpp_debug(DPP_DEBUG_TRACE, "connector is signed by recognized configurator\n");
    
    /*
     * ...then validate the connector
     */
    if (validate_connector(connector, connector_len,
                           peer->configurator_signkey, bnctx) < 0) {
        dpp_debug(DPP_DEBUG_ERR, "connector in DPP discovery frame is not valid!\n");
        return -1;
    }
    dpp_debug(DPP_DEBUG_TRACE, "connector in DPP Discovery frame is valid!\n");

    /*
     * extract the point from the valid connector, making sure it's same group as ours
     */
    if ((PK = get_point_from_connector(connector, connector_len, dpp_instance.group, bnctx)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "can't extract point from connector!\n");
        goto fail;;
    }
    if (((nk = EC_KEY_get0_private_key(peer->my_proto)) == NULL) ||
        ((NK = EC_KEY_get0_public_key(peer->my_proto)) == NULL)) {
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
    memset(pmk, 0, SHA512_DIGEST_LENGTH);
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
    print_buffer("pmkid", pmkid, 16);   /* PMKID is fixed at 128 bits */

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

int
process_dpp_discovery_frame (unsigned char *data, int len, dpp_handle handle)
{
    TLV *tlv;
    unsigned char tid;
    struct candidate *peer = NULL;
    dpp_action_frame *frame = (dpp_action_frame *)data;

    dpp_debug(DPP_DEBUG_TRACE, "got a DPP discovery frame!\n");
    TAILQ_FOREACH(peer, &dpp_instance.peers, entry) {
        if (peer->handle == handle) {
            break;
        }
    }
    if (peer == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to find peer to respond to discovery frame!\n");
        return -1;
    }
    srv_rem_timeout(srvctx, peer->t0);
    ieee_ize_attributes(frame->attributes, len - sizeof(dpp_action_frame));

    tlv = (TLV *)frame->attributes;
    if (TLV_type(tlv) != TRANSACTION_IDENTIFIER) {
        dpp_debug(DPP_DEBUG_ERR, "1st TLV in dpp discovery request was not a transaction ID!\n");
        return -1;
    }
    memcpy(&tid, TLV_value(tlv), 1);
    tlv = TLV_next(tlv);
    if (TLV_type(tlv) != CONNECTOR) {
        dpp_debug(DPP_DEBUG_ERR, "2nd TLV in dpp discovery request was not a connector!\n");
        return -1;
    }
    switch (frame->frame_type) {
        case DPP_SUB_PEER_DISCOVER_REQ:
            if (peer->connector == NULL || peer->connector_len < 1) {
                dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "No connector to send back, discarding DPP Discovery Request!\n");
                return 1;
            }
            if (peer->configurator_signkey == NULL) {
                dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "No configurator signing key, discarding DPP Discovery Request!\n");
                return 1;
            }
            if (process_dpp_discovery_connector(peer, TLV_value(tlv), TLV_length(tlv)) < 1) {
                dpp_debug(DPP_DEBUG_ERR, "failed to process dpp discovery request!\n");
                return -1;
            }
            send_dpp_discovery_frame(peer, DPP_SUB_PEER_DISCOVER_RESP, tid);
            break;
        case DPP_SUB_PEER_DISCOVER_RESP:
            if (tid != peer->discovery_transaction) {
                dpp_debug(DPP_DEBUG_ERR, "got a spurious DPP Discovery Response (%d, expected %d)\n",
                          tid, peer->discovery_transaction);
                return -1;
            }
            if (process_dpp_discovery_connector(peer, TLV_value(tlv), TLV_length(tlv)) < 1) {
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
// DPP configuration exchange routines
//----------------------------------------------------------------------

/*
 * dump the connector and network access key in aformat suitable for 
 * hostapd/wpa_supplicant-- this is the stuff to use to connect.
 */
static void
dump_key_con (struct candidate *peer)
{
    FILE *fp;
    char *buf;
    int buflen, i;

    /*
     * write out the connector...
     */
    if ((fp = fopen("connector.pem", "w")) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to store the connector!\n");
        return;
    }
    if ((buf = malloc(peer->connector_len + 1)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to copy the connector!\n");
        return;
    }
    memcpy(buf, peer->connector, peer->connector_len);
    buf[peer->connector_len] = '\0';
    fprintf(fp, "%s\n", buf);
    free(buf);
    fclose(fp);

    buf = NULL;
    /*
     * ...and the private key
     */
    buflen = i2d_ECPrivateKey(peer->my_proto, (unsigned char **)&buf);
    if ((fp = fopen("netaccesskey", "w")) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to store the network access key!\n");
        return;
    }
    for (i = 0; i < buflen; i++) {
        fprintf(fp, "%02x", buf[i] & 0xff);
    }

    fflush(fp);
    fclose(fp);
    OPENSSL_free(buf);
}

static int
send_dpp_config_resp_frame (struct candidate *peer, unsigned char status)
{
    siv_ctx ctx;
    TLV *tlv, *wraptlv;
    unsigned char burlx[256], burly[256], kid[SHA512_DIGEST_LENGTH];
    unsigned char connector[1024], *bn = NULL;
    char confobj[1536];
    int sofar = 0, offset, burllen, nid;
    BIGNUM *x = NULL, *y = NULL, *signprime = NULL;
    const EC_POINT *signpub;
    const EC_GROUP *signgroup;

    memset(peer->buffer, 0, sizeof(peer->buffer));
    peer->bufferlen = 0;
    
    tlv = (TLV *)peer->buffer;
    wraptlv = TLV_set_tlv(tlv, DPP_STATUS, 1, &status);
    wraptlv->type = WRAPPED_DATA;
    tlv = (TLV *)(wraptlv->value + AES_BLOCK_SIZE);
    tlv = TLV_set_tlv(tlv, ENROLLEE_NONCE, dpp_instance.noncelen, peer->enonce);

    /*
     * if we can't generate a connector then indicate configuration failure
     */
    if (generate_connector(connector, sizeof(connector), (EC_GROUP *)dpp_instance.group,
                           peer->peer_proto, peer->enrollee_role,
                           dpp_instance.signkey, bnctx) < 0) {
        dpp_debug(DPP_DEBUG_ERR, "unable to create a connector!\n");
        status = STATUS_CONFIGURE_FAILURE;
        goto problemo;
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

problemo:
    /*
     * if we're go then cons up a configuration object
     */
    if (status == STATUS_OK) {
        nid = EC_GROUP_get_curve_name(signgroup);
        sofar = snprintf(confobj, sizeof(confobj),
                         "{\"wi-fi_tech\":\"infra\",\"discovery\":{\"ssid\":\"goaway\",\"op_cl\":81,"
                         "\"ch_list\":[{\"ch\":11}]},\"cred\":{\"akm\":\"dpp\",\"signedConnector\":"
                         "\"%s\",\"csign\":{\"kty\":\"EC\",\"crv\":\"%s\","
                         "\"x\":\"%s\",\"y\":\"%s\",\"kid\":\"%s\"},"
                         "\"expiry\":\"2020-01-01T01:01:01\"}}",
                         connector,
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
                         burlx, burly, kid);
        tlv = TLV_set_tlv(tlv, CONFIGURATION_OBJECT, sofar, (unsigned char *)confobj);
    }

    wraptlv->length = (int)((unsigned char *)tlv - (unsigned char *)wraptlv->value);
    /*
     * datalen ends up being the amount of stuff we need to wrap (exclude the SIV)
     */
    peer->bufferlen = (int)((unsigned char *)tlv - peer->buffer);
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
    siv_encrypt(&ctx, wraptlv->value + AES_BLOCK_SIZE, wraptlv->value + AES_BLOCK_SIZE,
                wraptlv->length - AES_BLOCK_SIZE, wraptlv->value, 1, &peer->buffer,
                (int)((unsigned char *)wraptlv - (unsigned char *)peer->buffer));

    (void)send_dpp_config_frame(peer, GAS_INITIAL_RESPONSE);
    
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
    int ret = -1, caolen = 0;
    char confattsobj[80], whoami[20];
    
    memset(peer->buffer, 0, sizeof(peer->buffer));
    peer->nextfragment = 0;     // so enrollee can reuse the buffer when he's done sending
    peer->bufferlen = 0;
    peer->dialog_token = 1;

    if (gethostname(whoami, sizeof(whoami)) < 0) {
        dpp_debug(DPP_DEBUG_ERR, "unable to determine hostname!\n");
        strcpy(whoami, "dunno");
    }
    if (!RAND_bytes(peer->enonce, dpp_instance.noncelen)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to generate nonce for config request!\n");
        goto fin;
    }

    tlv = (TLV *)peer->buffer;
    tlv->type = WRAPPED_DATA;
    tlv = (TLV *)(tlv->value + AES_BLOCK_SIZE);

    tlv = TLV_set_tlv(tlv, ENROLLEE_NONCE, dpp_instance.noncelen, peer->enonce);
    caolen = snprintf(confattsobj, sizeof(confattsobj),
                      "{ \"name\":\"%s\", \"wi-fi_tech\":\"infra\", \"netRole\":\"%s\"}",
                      whoami, dpp_instance.enrollee_role);
    tlv = TLV_set_tlv(tlv, CONFIG_ATTRIBUTES_OBJECT, caolen, (unsigned char *)confattsobj);

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
    tlv->length = peer->bufferlen - sizeof(TLV);

    siv_encrypt(&ctx, tlv->value + AES_BLOCK_SIZE, tlv->value + AES_BLOCK_SIZE, tlv->length - AES_BLOCK_SIZE,
                tlv->value, 0);

    if (send_dpp_config_frame(peer, GAS_INITIAL_REQUEST)) {
        peer->retrans = 0;
        peer->t0 = srv_add_timeout(srvctx, SRV_SEC(2), retransmit_config, peer);
    }
    ret = 1;
fin:
    return ret;
}

static int
process_dpp_config_response (struct candidate *peer, unsigned char *attrs, int len)
{
    TLV *tlv;
    unsigned char *val, unb64url[1024], coordbin[P521_COORD_LEN];
    BIGNUM *x = NULL, *y = NULL;
    const EC_POINT *P;
    const EC_GROUP *signgroup;
    siv_ctx ctx;
    char *sstr, *estr, *dot;
    int ntok, ncred, unburllen, cl, coordlen, signnid, ret = -1;

    dpp_debug(DPP_DEBUG_TRACE, "got a DPP config response!\n");

    ieee_ize_attributes(attrs, len);
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
    if (siv_decrypt(&ctx, TLV_value(tlv) + AES_BLOCK_SIZE, TLV_value(tlv) + AES_BLOCK_SIZE,
                    TLV_length(tlv) - AES_BLOCK_SIZE, TLV_value(tlv), 1, attrs,
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
    if (*val != STATUS_OK) {
        dpp_debug(DPP_DEBUG_ERR, "Configurator returned %d as status in DPP Config Response: FAIL!\n",
                  *val);
        goto fin;
    }
    tlv = TLV_next(tlv);
    if (TLV_type(tlv) != CONFIGURATION_OBJECT) {
        dpp_debug(DPP_DEBUG_ERR, "No Configuration Object in the DPP Config response!\n");
        goto fin;
    }
    printf("\ncredential object:\n");
    printf("%.*s\n\n", TLV_length(tlv), TLV_value(tlv));
    if ((ncred = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                               &sstr, &estr, 2, "cred", "akm")) == 0) {
        dpp_debug(DPP_DEBUG_ERR, "No AKM credential in DPP Config response!\n");
        goto fin;
    }
    if (ncred < 1) {
        dpp_debug(DPP_DEBUG_ERR, "Got back %d credentials... bailing!\n", ncred);
        goto fin;
    }
    printf("we got back %d credential(s): %.*s\n", ncred, (int)(estr - sstr), sstr);
    if (strncmp(sstr, "dpp", 3) == 0) {
        /*
         * we got a connector!
         */
        if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                  &sstr, &estr, 2, "cred", "signedConnector")) == 0) {
            dpp_debug(DPP_DEBUG_ERR, "No connector in DPP Config response!\n");
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
        printf("connector is signed with %.*s, ", (int)(estr - sstr), sstr);
        if ((ntok = get_json_data((char *)unb64url, unburllen, &sstr, &estr, 1, "kid")) != 1) {
            dpp_debug(DPP_DEBUG_ERR, "Failed to get 'kid' from JWS Protected Header!\n");
            goto fin;
        }
        printf("by key with key id:\n %.*s\n", (int)(estr - sstr), sstr);
        /*
         * get the Configurator's signing key from the "csign" portion of the DPP Config Object
         */
        if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                  &sstr, &estr, 3, "cred", "csign", "crv")) != 1) {
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
        if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                  &sstr, &estr, 3, "cred", "csign", "x")) != 1) {
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
        if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                  &sstr, &estr, 3, "cred", "csign", "y")) != 1) {
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
        peer->configurator_signkey = EC_KEY_new_by_curve_name(signnid);
        EC_KEY_set_public_key_affine_coordinates(peer->configurator_signkey, x, y);
        EC_KEY_set_conv_form(peer->configurator_signkey, POINT_CONVERSION_COMPRESSED);
        EC_KEY_set_asn1_flag(peer->configurator_signkey, OPENSSL_EC_NAMED_CURVE);
        if (((signgroup = EC_KEY_get0_group(peer->configurator_signkey)) == NULL) ||
            ((P = EC_KEY_get0_public_key(peer->configurator_signkey)) == NULL) ||
            !EC_POINT_is_on_curve(signgroup, P, bnctx)) {
            dpp_debug(DPP_DEBUG_ERR, "configurator's signing key is not valid!\n");
            goto fin;
        }
        dpp_debug(DPP_DEBUG_TRACE, "configurator's signing key is valid!!!\n");

        if (get_kid_from_point(peer->csign_kid, signgroup, P, bnctx) < KID_LENGTH) {
            dpp_debug(DPP_DEBUG_ERR, "can't get key id for configurator's sign key!\n");
            goto fin;
        }
        
        /*
         * validate the connector
         */
        if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                  &sstr, &estr, 2, "cred", "signedConnector")) == 0) {
            dpp_debug(DPP_DEBUG_ERR, "No connector in DPP Config response!\n");
            goto fin;
        }
        if (validate_connector((unsigned char *)sstr, (int)(estr - sstr), peer->configurator_signkey, bnctx) < 0) {
            dpp_debug(DPP_DEBUG_ERR, "signature on connector is bad!\n");
            goto fin;
        }
        peer->connector_len = (int)(estr - sstr);
        if ((peer->connector = malloc(peer->connector_len)) == NULL) {
            peer->connector_len = 0;
            dpp_debug(DPP_DEBUG_ERR, "Unable to allocate a connector!!\n");
            goto fin;
        }
        memcpy(peer->connector, sstr, peer->connector_len);

        dump_key_con(peer);

        if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                  &sstr, &estr, 2, "discovery", "ssid")) == 0) {
            provision_connector(dpp_instance.enrollee_role, "*", 1,
                                peer->connector, peer->connector_len, peer->handle);
        } else {
            provision_connector(dpp_instance.enrollee_role, sstr, (int)(estr - sstr),
                                peer->connector, peer->connector_len, peer->handle);
        }
    } else if (strncmp(sstr, "psk", 3) == 0) {
        /*
         * got a PSK configuration!
         */
        if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                  &sstr, &estr, 2, "cred", "pass")) != 0) {
            printf("use passphrase '%.*s' ", (int)(estr - sstr), sstr);
        } else if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                         &sstr, &estr, 2, "cred", "psk_hex")) != 0) {
            printf("use hexstring '%.*s' ", (int)(estr - sstr), sstr);
        } else {
            dpp_debug(DPP_DEBUG_ERR, "Unknown type of psk, not 'pass' and not 'psk_hex'\n");
            goto fin;
        }
        if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                                  &sstr, &estr, 2, "discovery", "ssid")) == 0) {
            printf("with an any SSID I guess\n");
        } else {
            printf("with SSID %.*s\n", (int)(estr - sstr), sstr);
        }
    } else {
        dpp_debug(DPP_DEBUG_ERR, "Unknown credential type %.*s!\n", (int)(estr - sstr), sstr);
        goto fin;
    }
    ret = 1;
fin:
    if (ret < 1) {
        if (peer->configurator_signkey != NULL) {
            EC_KEY_free(peer->configurator_signkey);
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
process_dpp_config_request (struct candidate *peer, unsigned char *attrs, int len)
{
    TLV *tlv;
    int ntok;
    siv_ctx ctx;
    char *sstr, *estr;

    dpp_debug(DPP_DEBUG_TRACE, "got a DPP config request!\n");

    ieee_ize_attributes(attrs, len);
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
    ieee_ize_attributes(TLV_value(tlv) + AES_BLOCK_SIZE, TLV_length(tlv) - AES_BLOCK_SIZE);
    tlv = (TLV *)(TLV_value(tlv) + AES_BLOCK_SIZE);

    if (TLV_type(tlv) != ENROLLEE_NONCE) {
        dpp_debug(DPP_DEBUG_ERR, "malformed wrapped data in DPP Config Request-- no E-nonce!\n");
        return -1;
    }
    memcpy(peer->enonce, TLV_value(tlv), TLV_length(tlv));
    
    tlv = TLV_next(tlv);
    if (TLV_type(tlv) != CONFIG_ATTRIBUTES_OBJECT) {
        dpp_debug(DPP_DEBUG_ERR, "malformed wrapped data in DPP Config Request-- no C-attrs!\n");
        return -1;
    }
    /*
     * parse the config attributes object for some interesting info
     */
    if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                              &sstr, &estr, 1, "name")) == 0) {
        return -1;
    }
    dpp_debug(DPP_DEBUG_ANY, "there are %d result(s) for 'name': %.*s\n",
              ntok, estr - sstr, sstr);
    if ((estr - sstr) > sizeof(peer->enrollee_name)) {
        strncpy(peer->enrollee_name, sstr, sizeof(peer->enrollee_name));
    } else {
        strncpy(peer->enrollee_name, sstr, estr - sstr);
    }

    if ((ntok = get_json_data((char *)TLV_value(tlv), TLV_length(tlv),
                              &sstr, &estr, 1, "netRole")) == 0) {
        return -1;
    }
    dpp_debug(DPP_DEBUG_ANY, "there are %d result(s) for 'netRole': %.*s\n",
              ntok, estr - sstr, sstr);
    if ((estr - sstr) > sizeof(peer->enrollee_role)) {
        strncpy(peer->enrollee_role, sstr, sizeof(peer->enrollee_role));
    } else {
        strncpy(peer->enrollee_role, sstr, estr - sstr);
    }

    return 1;
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

    switch (field) {
        case GAS_INITIAL_REQUEST:
            dpp_debug(DPP_DEBUG_TRACE, "got a GAS_INITIAL_REQUEST...\n");
            if (peer->core != DPP_CONFIGURATOR) {
                return ret;
            }
            garq = (gas_action_req_frame *)data;
            if (memcmp(garq->ad_proto_elem, dpp_proto_elem_req, 2) ||
                memcmp(garq->ad_proto_id, dpp_proto_id, sizeof(dpp_proto_id))) {
                dpp_debug(DPP_DEBUG_ERR, "got an gas action frame, not a dpp config frame\n");
                return ret;
            }
            peer->dialog_token = garq->dialog_token;
            if (process_dpp_config_request(peer, garq->query_req, len - sizeof(gas_action_req_frame)) < 1) {
                dpp_debug(DPP_DEBUG_ERR, "error processing DPP Config request!\n");
                send_dpp_config_resp_frame(peer, STATUS_CONFIGURE_FAILURE);
            } else {
                send_dpp_config_resp_frame(peer, STATUS_OK);
            }
            break;
        case GAS_INITIAL_RESPONSE:
            dpp_debug(DPP_DEBUG_TRACE, "got a GAS_INITIAL_RESPONSE...\n");
            if (peer->core != DPP_ENROLLEE) {
                return ret;
            }
            garp = (gas_action_resp_frame *)data;
            if (memcmp(garp->ad_proto_elem, dpp_proto_elem_resp, 2) ||
                memcmp(garp->ad_proto_id, dpp_proto_id, sizeof(dpp_proto_id))) {
                dpp_debug(DPP_DEBUG_ERR, "got a gas action frame, not a dpp config frame\n");
                return ret;
            }
            dpp_debug(DPP_DEBUG_TRACE, "response len is %d, comeback delay is %d\n",
                      garp->query_resplen, garp->comeback_delay);
            if (garp->query_resplen) {
                /*
                 * if we got the query response then process it
                 */
                if (process_dpp_config_response(peer, garp->query_resp, len - sizeof(gas_action_resp_frame)) < 1) {
                    dpp_debug(DPP_DEBUG_ERR, "error processing DPP Config response!\n");
                    return -1;
                }
            } else if (garp->comeback_delay == 1) {
                /*
                 * otherwise the response is going to be fragmented, ask for 1st fragment
                 */
                send_dpp_config_frame(peer, GAS_COMEBACK_REQUEST);
            }
            break;
        case GAS_COMEBACK_REQUEST:
            dpp_debug(DPP_DEBUG_TRACE, "got a GAS_COMEBACK_REQUEST...\n");
            if (peer->core != DPP_CONFIGURATOR) {
                return ret;
            }
            /*
             * this frame is not secured in any way, all we can do is send next fragment...
             * ...check whether we've sent everything so we don't just continue to respond
             * to these things ad infinitum
             */
            if (peer->nextfragment < peer->bufferlen) {
                send_dpp_config_frame(peer, GAS_COMEBACK_RESPONSE);
            }
            break;
        case GAS_COMEBACK_RESPONSE:
            dpp_debug(DPP_DEBUG_TRACE, "got a GAS_COMEBACK_RESPONSE...\n");
            if (peer->core != DPP_ENROLLEE) {
                return ret;
            }
            gacrp = (gas_action_comeback_resp_frame *)data;
            if (memcmp(gacrp->ad_proto_elem, dpp_proto_elem_resp, 2) ||
                memcmp(gacrp->ad_proto_id, dpp_proto_id, sizeof(dpp_proto_id))) {
                dpp_debug(DPP_DEBUG_ERR, "got an gas action frame, not a dpp config frame\n");
                return ret;
            }
            if (gacrp->status_code) {
                dpp_debug(DPP_DEBUG_ERR, "got a gas comeback response with status %d\n",
                          gacrp->status_code);
                return ret;
            }
            if ((peer->nextfragment + gacrp->query_resplen) > sizeof(peer->buffer)) {
                dpp_debug(DPP_DEBUG_ERR, "a bit too many fragments\n");
            }
            /*
             * use the buffer and next fragment field since the enrollee is not using it
             */
            memcpy(peer->buffer + peer->nextfragment, gacrp->query_resp, gacrp->query_resplen);
            peer->nextfragment += gacrp->query_resplen;
            /*
             * if there's more fragments then ask for them, otherwise process the frame
             */
            if (gacrp->fragment_id & 0x80) {
                send_dpp_config_frame(peer, GAS_COMEBACK_REQUEST);
            } else {
                if (process_dpp_config_response(peer, peer->buffer, peer->nextfragment) < 1) {
                    dpp_debug(DPP_DEBUG_ERR, "error processing DPP Config response!\n");
                    return -1;
                }
            }
            break;
        default:
            break;
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
    dpp_debug(DPP_DEBUG_TRACE, "beginning DPP Config protocol\n");
    send_dpp_config_req_frame ((struct candidate *)data);
}

//----------------------------------------------------------------------
// DPP authentication exchange routines
//----------------------------------------------------------------------

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
    if (initiators != is_initiator) {
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
        if (!peer->mauth && !is_initiator) {
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
        debug_buffer(DPP_DEBUG_TRACE, !peer->mauth && !is_initiator ? "my bootstrap pubkey" : "peer's bootstrap pubkey",
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
        if (!peer->mauth && is_initiator) {
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
        debug_buffer(DPP_DEBUG_TRACE, !peer->mauth && is_initiator ? "peer's bootstrap pubkey" : "my bootstrap pubkey",
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
    if (is_initiator) {
        memcpy(salt, peer->mynonce, dpp_instance.noncelen);
        memcpy(salt+dpp_instance.noncelen, peer->peernonce, dpp_instance.noncelen);
    } else {
        memcpy(salt, peer->peernonce, dpp_instance.noncelen);
        memcpy(salt+dpp_instance.noncelen, peer->mynonce, dpp_instance.noncelen);
    }
    /*
     * and compute ke from ikm
     */
    if (peer->mauth && l != NULL) {
        hkdf(dpp_instance.hashfcn, 0,
             ikm, 3 * dpp_instance.primelen,
             salt, 2*dpp_instance.noncelen,
             (unsigned char *)"DPP Key", strlen("DPP Key"),
             peer->ke, dpp_instance.digestlen);
    } else {
        hkdf(dpp_instance.hashfcn, 0,
             ikm, 2 * dpp_instance.primelen,
             salt, 2*dpp_instance.noncelen,
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
    unsigned char bootkeyhash[SHA256_DIGEST_LENGTH], *ptr, *attrs;
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
    tlv->length = ieee_order(sizeof(TLV) + AES_BLOCK_SIZE + dpp_instance.digestlen);
    ptr = tlv->value;
    /*
     * ...which is itself a TLV, the initiator auth tag
     */
    tlv = (TLV *)(ptr + AES_BLOCK_SIZE);

    /*
     * set up the DPP action frame header for inclusion as part of AAD
     */
    setup_dpp_auth_frame(peer, DPP_SUB_AUTH_CONFIRM);
    if (status == STATUS_OK) {
        tlv->type = INITIATOR_AUTH_TAG;
        tlv->length = ieee_order(dpp_instance.digestlen);
        dpp_debug(DPP_DEBUG_TRACE, "I-auth...\n");  // delete this
        if (generate_auth(peer, 1, tlv->value) != dpp_instance.digestlen) {
            goto fin;
        }
        debug_buffer(DPP_DEBUG_TRACE, "AUTHi", tlv->value, dpp_instance.digestlen);
        fflush(stdout);
        tlv = TLV_next(tlv);

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
         */
        tlv->type = RESPONDER_NONCE;
        tlv->length = ieee_order(dpp_instance.noncelen);
        memcpy(tlv->value, peer->peernonce, dpp_instance.noncelen);
        tlv = TLV_next(tlv);
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
    peer->bufferlen = (int)((unsigned char *)tlv - peer->buffer);
    if (send_dpp_auth_frame(peer)) {
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
    setup_dpp_auth_frame(peer, DPP_SUB_AUTH_RESPONSE);
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
        secondarywrap->type = RESPONDER_AUTH_TAG;
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
        ieee_ize_attributes(primary + AES_BLOCK_SIZE, ptr - (primary + AES_BLOCK_SIZE));
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
         * fix up the lengths we skipped over and send back an notification
         */
        ptr = (unsigned char *)primarywrap;
        tlv->length = primarywraplen = ptr - primary;
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
    
    /*
     * and now ieee-ize our message
     */
    ieee_ize_attributes(attrs, ptr - attrs);
    peer->bufferlen = (int)(ptr - peer->buffer);
    if (send_dpp_auth_frame(peer)) {
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
    ieee_ize_attributes(wrap, wrapped_len);

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
    ieee_ize_attributes(attrs, (int)((unsigned char *)tlv - attrs));

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
        tlv = TLV_next(tlv);
    }

    /*
     * ...and now wrap the wrapped data
     */
    tlv->type = WRAPPED_DATA;
    tlv->length = AES_BLOCK_SIZE + wrapped_len;      /* IV || C */

    /*
     * setup DPP Action frame header to include as a component of AAD
     */
    setup_dpp_auth_frame(peer, DPP_SUB_AUTH_REQUEST);
    siv_encrypt(&ctx, wrap, (TLV_value(tlv) + AES_BLOCK_SIZE),
                wrapped_len, TLV_value(tlv),
                2, peer->frame, sizeof(dpp_action_frame), attrs, ((unsigned char *)tlv - attrs));

    /*
     * ptr points to the end of all the attributes now
     */
    ptr = (unsigned char *)TLV_next(tlv);
        
    ieee_ize_attributes(attrs, ptr - attrs);
    peer->bufferlen = (int)(ptr - peer->buffer);
    if (send_dpp_auth_frame(peer)) {
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
    ieee_ize_attributes(TLV_value(tlv) + AES_BLOCK_SIZE, TLV_length(tlv) - AES_BLOCK_SIZE);
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
        ieee_ize_attributes(ptr, primarywraplen);
        if ((tlv = find_tlv(RESPONDER_CAPABILITIES, ptr, primarywraplen)) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "can't find responder capabilities in primary wrapped data\n");
            goto fin;
        }
        if (*val == STATUS_RESPONSE_PENDING) {
            /*
             * give the guy 20s to get our bootstrapping key.... then destroy him.
             */
            peer->t0 = srv_add_timeout(srvctx, SRV_SEC(20), destroy_peer, peer);
            return 1;
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
     * and unwrap it
     */
    if (siv_decrypt(&ctx, ptr, ptr, primarywraplen, TLV_value(tlv),
                    2, frame, sizeof(dpp_action_frame), attrs, ((unsigned char *)tlv - attrs)) < 1) {
        dpp_debug(DPP_DEBUG_ERR, "can't decrypt primary blob in DPP Auth Resp!\n");
        /*
         * TODO: send dpp_auth_confirm with a status of STATUS_DECRYPT_FAILURE
         */
        goto fin;
    }
    ieee_ize_attributes(ptr, primarywraplen);

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
    ieee_ize_attributes(TLV_value(tlv) + AES_BLOCK_SIZE, TLV_length(tlv) - AES_BLOCK_SIZE);
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
    ieee_ize_attributes(frame->attributes, len - sizeof(dpp_action_frame));
    /*
     * implement the state machine for DPP
     */
    if (is_initiator) {
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

    return 1;
}

static void
init_dpp_auth (timerid id, void *data)
{
    struct candidate *peer = (struct candidate *)data;

    if (send_dpp_auth_request(peer) > 0) {
        peer->state = DPP_AUTHENTICATING;
    }
    return;
}

dpp_handle
dpp_create_peer (char *keyb64)
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
    peer->mauth = dpp_instance.mauth;   /* initiator changes, responder set */
    
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
    } else if (is_initiator) {
        dpp_debug(DPP_DEBUG_ERR, "Initiator needs responder's bootstrapping key!\n");
        EC_POINT_free(peer->peer_proto);
        free(peer);
        return -1;
    }
    
    peer->configurator_signkey = NULL;  // even if this is a configurator, used by discovery
    peer->connector = NULL;
    peer->connector_len = 0;
    peer->state = DPP_BOOTSTRAPPED;
    TAILQ_INSERT_HEAD(&dpp_instance.peers, peer, entry);

    peer->handle = ++next_handle; // safe to assume we won't have 2^32 active sessions

    dpp_debug(DPP_DEBUG_TRACE, "\n------- Start of DPP Authentication Protocol ---------\n");
    if (is_initiator) {
        peer->t0 = srv_add_timeout(srvctx, SRV_MSEC(200), init_dpp_auth, peer);
    }
    return peer->handle;
}

int
dpp_initialize (int initiator, int core, int mutual, char *keyfile, 
                char *signkeyfile, char *enrolleerole, int opclass, int channel, int verbosity)
{
    FILE *fp;
    BIO *bio = NULL;
    int ret = 0;
    BIGNUM *prime = NULL;

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
    is_initiator = initiator;
    if (!is_initiator) {
        /*
         * the responder decides, the initiator always offers
         */
        dpp_instance.mauth = mutual;
    } else {
        dpp_instance.mauth = 1;
    }

    if (!core) {                /* have to chose one! */
        return -1;
    }
    dpp_instance.core = core;
    switch (core) {
        case DPP_ENROLLEE:
            dpp_debug(DPP_DEBUG_TRACE, "role: enrollee, %s\n",
                      is_initiator ? "initiator" : mutual ? "responder (mutual auth)" : "responder (not mutual auth)");
            break;
        case DPP_CONFIGURATOR:
            dpp_debug(DPP_DEBUG_TRACE, "role: configurator, %s\n",
                      is_initiator ? "initiator" : mutual ? "responder (mutual auth)" : "responder (not mutual auth)");
            break;
        case (DPP_ENROLLEE | DPP_CONFIGURATOR):
            dpp_debug(DPP_DEBUG_TRACE, "role: both enrollee and configurator, %s\n",
                      is_initiator ? "initiator" : mutual ? "responder (mutual auth)" : "responder (not mutual auth)");
            break;
        default:
            dpp_debug(DPP_DEBUG_TRACE, "role: unknown... %x\n", core);
    }

    /*
     * if we're the configurator get the signing key...
     */
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
    } else {
        strcpy(dpp_instance.enrollee_role, enrolleerole);
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

    /*
     * figure out what group our bootstrap key is in and how big that 
     * prime is (handy when constructing and parsing messages)
     */
    if (((dpp_instance.group = EC_KEY_get0_group(dpp_instance.bootstrap)) == NULL) ||
        ((prime = BN_new()) == NULL) ||
        !EC_GROUP_get_curve_GFp(dpp_instance.group, prime, NULL, NULL, bnctx)) {
        fprintf(stderr, "DDP: unable to get group of bootstrap key\n");
        ret = -1;
        goto fin;
    }
    dpp_instance.primelen = BN_num_bytes(prime);
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
    dpp_instance.noncelen = dpp_instance.digestlen/2;
    EVP_add_digest(dpp_instance.hashfcn);
    if (dpp_instance.hashfcn != EVP_sha256()) {
        EVP_add_digest(EVP_sha256());   /* to hash bootstrapping keys */
    }
    TAILQ_INIT(&dpp_instance.peers);
    ret = 1;
fin:
    if (prime != NULL) {
        BN_free(prime);
    }
    return ret;
}


