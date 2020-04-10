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
#ifdef FREEBSD
#include "helpers.h"
#endif  /* FREEBSD */

/*
 * PKEX debugging bitmasks
 */
#define DPP_DEBUG_ERR           0x01
#define DPP_DEBUG_PROTOCOL_MSG  0x02
#define DPP_DEBUG_STATE_MACHINE 0x04
#define DPP_DEBUG_CRYPTO        0x08
#define DPP_DEBUG_CRYPTO_VERB   0x10
#define DPP_DEBUG_TRACE         0x20
#define DPP_DEBUG_ANY           0xffff

/*
 * PKEX status codes
 */
#define STATUS_OK               0
#define ERROR_BAD_GROUP         4

typedef dpp_action_frame pkex_frame;

extern service_context srvctx;

struct pkex_peer {
    TAILQ_ENTRY(pkex_peer) entry;
    unsigned char mymac[ETH_ALEN];
    unsigned char peermac[ETH_ALEN];
    unsigned char initiator;
    /*
     * PKEX stuff
     */
    EC_KEY *X;                  /* my ephemeral key */
    EC_POINT *Y;                /* peer's ephemeral key */
    BIGNUM *m;                  /* x-coord of our encrypted key */
    BIGNUM *n;                  /* x-coord of peer's encrypted key */
    unsigned char z[SHA512_DIGEST_LENGTH]; /* shared secret */
    EC_KEY *peer_bootstrap;
    unsigned char k[SHA512_DIGEST_LENGTH];
    timerid t0;                           
    int retrans;
#define PKEX_NOTHING            1
#define PKEX_SEND_EXCHANGE      2
#define PKEX_SEND_COMREV        3
#define PKEX_FINISHED           4
    unsigned short state;
    unsigned char peernonce[SHA512_DIGEST_LENGTH];
    unsigned char mynonce[SHA512_DIGEST_LENGTH];
};

#define state_to_string(x) (x) == PKEX_NOTHING ? "PKEX NOTHING" : \
                           (x) == PKEX_SEND_EXCHANGE ? "PKEX EXCHANGED" : \
                           (x) == PKEX_SEND_COMREV ? "PKEX COMMITTED/REVEALED" : \
                           (x) == PKEX_FINISHED ? "PKEX FINISHED" : \
                           "unknown"

#define frame_to_string(x) (x) == PKEX_SUB_EXCH_REQ ? "PKEX Exchange Request" : \
                           (x) == PKEX_SUB_EXCH_RESP ? "PKEX Exchange Response" : \
                           (x) == PKEX_SUB_COM_REV_REQ ? "PKEX Commit/Reveal Request" : \
                           (x) == PKEX_SUB_COM_REV_RESP ? "PKEX Commit/Reveal Response" : \
                           "unknown"

/*
 * our instance of PKEX
 */
struct _pkex_instance {
    TAILQ_HEAD(blah, pkex_peer) peers;
    EC_KEY *bootstrap;
    const EC_GROUP *group;
    const EVP_MD *hashfcn;
    EC_POINT *Pme;
    EC_POINT *Ppeer;
    char bsfile[80];
    char password[80];
    char identifier[80];
    int adds_identifier;
    int opclass;                /* operating class running PKEX on*/
    int channel;                /* channel running PKEX on */
    int group_num;              /* these are handy to keep around */
    int primelen;               /* and not have to continually */
    int digestlen;              /* compute them from "bootstrap" */
    int nid;                    /* ditto */
} pkex_instance;

/*
 * global variables
 */
static BN_CTX *bnctx = NULL;
static int debug = 0;
static int init_or_resp;

static unsigned char wfa_dpp[4] = { 0x50, 0x6f, 0x9a, 0x1a };

/*
 * the role-specific elements
 */
unsigned char nist_p256_initiator_x_coord[32] = {
    0x56, 0x26, 0x12, 0xcf, 0x36, 0x48, 0xfe, 0x0b, 
    0x07, 0x04, 0xbb, 0x12, 0x22, 0x50, 0xb2, 0x54, 
    0xb1, 0x94, 0x64, 0x7e, 0x54, 0xce, 0x08, 0x07, 
    0x2e, 0xec, 0xca, 0x74, 0x5b, 0x61, 0x2d, 0x25
};
unsigned char nist_p256_initiator_y_coord[32] = {
    0x3e, 0x44, 0xc7, 0xc9, 0x8c, 0x1c, 0xa1, 0x0b, 
    0x20, 0x09, 0x93, 0xb2, 0xfd, 0xe5, 0x69, 0xdc, 
    0x75, 0xbc, 0xad, 0x33, 0xc1, 0xe7, 0xc6, 0x45, 
    0x4d, 0x10, 0x1e, 0x6a, 0x3d, 0x84, 0x3c, 0xa4
};
unsigned char nist_p256_responder_x_coord[32] = {
    0x1e, 0xa4, 0x8a, 0xb1, 0xa4, 0xe8, 0x42, 0x39, 
    0xad, 0x73, 0x07, 0xf2, 0x34, 0xdf, 0x57, 0x4f, 
    0xc0, 0x9d, 0x54, 0xbe, 0x36, 0x1b, 0x31, 0x0f, 
    0x59, 0x91, 0x52, 0x33, 0xac, 0x19, 0x9d, 0x76
};
unsigned char nist_p256_responder_y_coord[32] = {
    0xd9, 0xfb, 0xf6, 0xb9, 0xf5, 0xfa, 0xdf, 0x19, 
    0x58, 0xd8, 0x3e, 0xc9, 0x89, 0x7a, 0x35, 0xc1, 
    0xbd, 0xe9, 0x0b, 0x77, 0x7a, 0xcb, 0x91, 0x2a, 
    0xe8, 0x21, 0x3f, 0x47, 0x52, 0x02, 0x4d, 0x67
};

unsigned char nist_p384_initiator_x_coord[48] = {
    0x95, 0x3f, 0x42, 0x9e, 0x50, 0x7f, 0xf9, 0xaa, 
    0xac, 0x1a, 0xf2, 0x85, 0x2e, 0x64, 0x91, 0x68, 
    0x64, 0xc4, 0x3c, 0xb7, 0x5c, 0xf8, 0xc9, 0x53, 
    0x6e, 0x58, 0x4c, 0x7f, 0xc4, 0x64, 0x61, 0xac, 
    0x51, 0x8a, 0x6f, 0xfe, 0xab, 0x74, 0xe6, 0x12, 
    0x81, 0xac, 0x38, 0x5d, 0x41, 0xe6, 0xb9, 0xa3
};
unsigned char nist_p384_initiator_y_coord[48] = {
    0x76, 0x2f, 0x68, 0x84, 0xa6, 0xb0, 0x59, 0x29, 
    0x83, 0xa2, 0x6c, 0xa4, 0x6c, 0x3b, 0xf8, 0x56, 
    0x76, 0x11, 0x2a, 0x32, 0x90, 0xbd, 0x07, 0xc7, 
    0x37, 0x39, 0x9d, 0xdb, 0x96, 0xf3, 0x2b, 0xb6, 
    0x27, 0xbb, 0x29, 0x3c, 0x17, 0x33, 0x9d, 0x94, 
    0xc3, 0xda, 0xac, 0x46, 0xb0, 0x8e, 0x07, 0x18
};
unsigned char nist_p384_responder_x_coord[48] = {
    0xad, 0xbe, 0xd7, 0x1d, 0x3a, 0x71, 0x64, 0x98, 
    0x5f, 0xb4, 0xd6, 0x4b, 0x50, 0xd0, 0x84, 0x97, 
    0x4b, 0x7e, 0x57, 0x70, 0xd2, 0xd9, 0xf4, 0x92, 
    0x2a, 0x3f, 0xce, 0x99, 0xc5, 0x77, 0x33, 0x44, 
    0x14, 0x56, 0x92, 0xcb, 0xae, 0x46, 0x64, 0xdf, 
    0xe0, 0xbb, 0xd7, 0xb1, 0x29, 0x20, 0x72, 0xdf
};
unsigned char nist_p384_responder_y_coord[48] = {
    0xab, 0xa7, 0xdf, 0x52, 0xaa, 0xe2, 0x35, 0x0c, 
    0xe3, 0x75, 0x32, 0xe6, 0xbf, 0x06, 0xc8, 0x7c, 
    0x38, 0x29, 0x4c, 0xec, 0x82, 0xac, 0xd7, 0xa3, 
    0x09, 0xd2, 0x0e, 0x22, 0x5a, 0x74, 0x52, 0xa1, 
    0x7e, 0x54, 0x4e, 0xfe, 0xc6, 0x29, 0x33, 0x63, 
    0x15, 0xe1, 0x7b, 0xe3, 0x40, 0x1c, 0xca, 0x06
};

unsigned char nist_p521_initiator_x_coord[66] = {
    0x00, 0x16, 0x20, 0x45, 0x19, 0x50, 0x95, 0x23, 
    0x0d, 0x24, 0xbe, 0x00, 0x87, 0xdc, 0xfa, 0xf0, 
    0x58, 0x9a, 0x01, 0x60, 0x07, 0x7a, 0xca, 0x76, 
    0x01, 0xab, 0x2d, 0x5a, 0x46, 0xcd, 0x2c, 0xb5, 
    0x11, 0x9a, 0xff, 0xaa, 0x48, 0x04, 0x91, 0x38, 
    0xcf, 0x86, 0xfc, 0xa4, 0xa5, 0x0f, 0x47, 0x01, 
    0x80, 0x1b, 0x30, 0xa3, 0xae, 0xe8, 0x1c, 0x2e, 
    0xea, 0xcc, 0xf0, 0x03, 0x9f, 0x77, 0x4c, 0x8d, 
    0x97, 0x76
};
unsigned char nist_p521_initiator_y_coord[66] = {
    0x00, 0xb3, 0x8e, 0x02, 0xe4, 0x2a, 0x63, 0x59, 
    0x12, 0xc6, 0x10, 0xba, 0x3a, 0xf9, 0x02, 0x99, 
    0x3f, 0x14, 0xf0, 0x40, 0xde, 0x5c, 0xc9, 0x8b, 
    0x02, 0x55, 0xfa, 0x91, 0xb1, 0xcc, 0x6a, 0xbd, 
    0xe5, 0x62, 0xc0, 0xc5, 0xe3, 0xa1, 0x57, 0x9f, 
    0x08, 0x1a, 0xa6, 0xe2, 0xf8, 0x55, 0x90, 0xbf, 
    0xf5, 0xa6, 0xc3, 0xd8, 0x52, 0x1f, 0xb7, 0x02, 
    0x2e, 0x7c, 0xc8, 0xb3, 0x20, 0x1e, 0x79, 0x8d, 
    0x03, 0xa8
};
unsigned char nist_p521_responder_x_coord[66] = {
    0x00, 0x79, 0xe4, 0x4d, 0x6b, 0x5e, 0x12, 0x0a, 
    0x18, 0x2c, 0xb3, 0x05, 0x77, 0x0f, 0xc3, 0x44, 
    0x1a, 0xcd, 0x78, 0x46, 0x14, 0xee, 0x46, 0x3f, 
    0xab, 0xc9, 0x59, 0x7c, 0x85, 0xa0, 0xc2, 0xfb, 
    0x02, 0x32, 0x99, 0xde, 0x5d, 0xe1, 0x0d, 0x48, 
    0x2d, 0x71, 0x7d, 0x8d, 0x3f, 0x61, 0x67, 0x9e, 
    0x2b, 0x8b, 0x12, 0xde, 0x10, 0x21, 0x55, 0x0a, 
    0x5b, 0x2d, 0xe8, 0x05, 0x09, 0xf6, 0x20, 0x97, 
    0x84, 0xb4
};
unsigned char nist_p521_responder_y_coord[66] = {
    0x00, 0x46, 0x63, 0x39, 0xbe, 0xcd, 0xa4, 0x2d, 
    0xca, 0x27, 0x74, 0xd4, 0x1b, 0x91, 0x33, 0x20, 
    0x83, 0xc7, 0x3b, 0xa4, 0x09, 0x8b, 0x8e, 0xa3, 
    0x88, 0xe9, 0x75, 0x7f, 0x56, 0x7b, 0x38, 0x84, 
    0x62, 0x02, 0x7c, 0x90, 0x51, 0x07, 0xdb, 0xe9, 
    0xd0, 0xde, 0xda, 0x9a, 0x5d, 0xe5, 0x94, 0xd2, 
    0xcf, 0x9d, 0x4c, 0x33, 0x91, 0xa6, 0xc3, 0x80, 
    0xa7, 0x6e, 0x7e, 0x8d, 0xf8, 0x73, 0x6e, 0x53, 
    0xce, 0xe1
};

#ifdef HAS_BRAINPOOL
unsigned char brainpool_p256_initiator_x_coord[32] = {
    0x46, 0x98, 0x18, 0x6c, 0x27, 0xcd, 0x4b, 0x10, 
    0x7d, 0x55, 0xa3, 0xdd, 0x89, 0x1f, 0x9f, 0xca, 
    0xc7, 0x42, 0x5b, 0x8a, 0x23, 0xed, 0xf8, 0x75, 
    0xac, 0xc7, 0xe9, 0x8d, 0xc2, 0x6f, 0xec, 0xd8
};
unsigned char brainpool_p256_initiator_y_coord[32] = {
    0x93, 0xca, 0xef, 0xa9, 0x66, 0x3e, 0x87, 0xcd, 
    0x52, 0x6e, 0x54, 0x13, 0xef, 0x31, 0x67, 0x30, 
    0x15, 0x13, 0x9d, 0x6d, 0xc0, 0x95, 0x32, 0xbe, 
    0x4f, 0xab, 0x5d, 0xf7, 0xbf, 0x5e, 0xaa, 0x0b
};
unsigned char brainpool_p256_responder_x_coord[32] = {
    0x90, 0x18, 0x84, 0xc9, 0xdc, 0xcc, 0xb5, 0x2f, 
    0x4a, 0x3f, 0x4f, 0x18, 0x0a, 0x22, 0x56, 0x6a, 
    0xa9, 0xef, 0xd4, 0xe6, 0xc3, 0x53, 0xc2, 0x1a, 
    0x23, 0x54, 0xdd, 0x08, 0x7e, 0x10, 0xd8, 0xe3
};
unsigned char brainpool_p256_responder_y_coord[32] = {
    0x2a, 0xfa, 0x98, 0x9b, 0xe3, 0xda, 0x30, 0xfd, 
    0x32, 0x28, 0xcb, 0x66, 0xfb, 0x40, 0x7f, 0xf2, 
    0xb2, 0x25, 0x80, 0x82, 0x44, 0x85, 0x13, 0x7e, 
    0x4b, 0xb5, 0x06, 0xc0, 0x03, 0x69, 0x23, 0x64
};

unsigned char brainpool_p384_initiator_x_coord[48] = {
    0x0a, 0x2c, 0xeb, 0x49, 0x5e, 0xb7, 0x23, 0xbd, 
    0x20, 0x5b, 0xe0, 0x49, 0xdf, 0xcf, 0xcf, 0x19, 
    0x37, 0x36, 0xe1, 0x2f, 0x59, 0xdb, 0x07, 0x06, 
    0xb5, 0xeb, 0x2d, 0xae, 0xc2, 0xb2, 0x38, 0x62, 
    0xa6, 0x73, 0x09, 0xa0, 0x6c, 0x0a, 0xa2, 0x30, 
    0x99, 0xeb, 0xf7, 0x1e, 0x47, 0xb9, 0x5e, 0xbe
};
unsigned char brainpool_p384_initiator_y_coord[48] = {
    0x54, 0x76, 0x61, 0x65, 0x75, 0x5a, 0x2f, 0x99, 
    0x39, 0x73, 0xca, 0x6c, 0xf9, 0xf7, 0x12, 0x86, 
    0x54, 0xd5, 0xd4, 0xad, 0x45, 0x7b, 0xbf, 0x32, 
    0xee, 0x62, 0x8b, 0x9f, 0x52, 0xe8, 0xa0, 0xc9, 
    0xb7, 0x9d, 0xd1, 0x09, 0xb4, 0x79, 0x1c, 0x3e, 
    0x1a, 0xbf, 0x21, 0x45, 0x66, 0x6b, 0x02, 0x52
};
unsigned char brainpool_p384_responder_x_coord[48] = {
    0x03, 0xa2, 0x57, 0xef, 0xe8, 0x51, 0x21, 0xa0, 
    0xc8, 0x9e, 0x21, 0x02, 0xb5, 0x9a, 0x36, 0x25, 
    0x74, 0x22, 0xd1, 0xf2, 0x1b, 0xa8, 0x9a, 0x9b, 
    0x97, 0xbc, 0x5a, 0xeb, 0x26, 0x15, 0x09, 0x71, 
    0x77, 0x59, 0xec, 0x8b, 0xb7, 0xe1, 0xe8, 0xce, 
    0x65, 0xb8, 0xaf, 0xf8, 0x80, 0xae, 0x74, 0x6c
};
unsigned char brainpool_p384_responder_y_coord[48] = {
    0x2f, 0xd9, 0x6a, 0xc7, 0x3e, 0xec, 0x76, 0x65, 
    0x2d, 0x38, 0x7f, 0xec, 0x63, 0x26, 0x3f, 0x04, 
    0xd8, 0x4e, 0xff, 0xe1, 0x0a, 0x51, 0x74, 0x70, 
    0xe5, 0x46, 0x63, 0x7f, 0x5c, 0xc0, 0xd1, 0x7c, 
    0xfb, 0x2f, 0xea, 0xe2, 0xd8, 0x0f, 0x84, 0xcb, 
    0xe9, 0x39, 0x5c, 0x64, 0xfe, 0xcb, 0x2f, 0xf1
};

unsigned char brainpool_p512_initiator_x_coord[64] = {
    0x4c, 0xe9, 0xb6, 0x1c, 0xe2, 0x00, 0x3c, 0x9c, 
    0xa9, 0xc8, 0x56, 0x52, 0xaf, 0x87, 0x3e, 0x51, 
    0x9c, 0xbb, 0x15, 0x31, 0x1e, 0xc1, 0x05, 0xfc, 
    0x7c, 0x77, 0xd7, 0x37, 0x61, 0x27, 0xd0, 0x95, 
    0x98, 0xee, 0x5d, 0xa4, 0x3d, 0x09, 0xdb, 0x3d, 
    0xfa, 0x89, 0x9e, 0x7f, 0xa6, 0xa6, 0x9c, 0xff, 
    0x83, 0x5c, 0x21, 0x6c, 0x3e, 0xf2, 0xfe, 0xdc, 
    0x63, 0xe4, 0xd1, 0x0e, 0x75, 0x45, 0x69, 0x0f
};
unsigned char brainpool_p512_initiator_y_coord[64] = {
    0x50, 0xb5, 0x9b, 0xfa, 0x45, 0x67, 0x75, 0x94, 
    0x44, 0xe7, 0x68, 0xb0, 0xeb, 0x3e, 0xb3, 0xb8, 
    0xf9, 0x99, 0x05, 0xef, 0xae, 0x6c, 0xbc, 0xe3, 
    0xe1, 0xd2, 0x51, 0x54, 0xdf, 0x59, 0xd4, 0x45, 
    0x41, 0x3a, 0xa8, 0x0b, 0x76, 0x32, 0x44, 0x0e, 
    0x07, 0x60, 0x3a, 0x6e, 0xbe, 0xfe, 0xe0, 0x58, 
    0x52, 0xa0, 0xaa, 0x8b, 0xd8, 0x5b, 0xf2, 0x71, 
    0x11, 0x9a, 0x9e, 0x8f, 0x1a, 0xd1, 0xc9, 0x99
};
unsigned char brainpool_p512_responder_x_coord[64] = {
    0x2a, 0x60, 0x32, 0x27, 0xa1, 0xe6, 0x94, 0x72, 
    0x1c, 0x48, 0xbe, 0xc5, 0x77, 0x14, 0x30, 0x76, 
    0xe4, 0xbf, 0xf7, 0x7b, 0xc5, 0xfd, 0xdf, 0x19, 
    0x1e, 0x0f, 0xdf, 0x1c, 0x40, 0xfa, 0x34, 0x9e, 
    0x1f, 0x42, 0x24, 0xa3, 0x2c, 0xd5, 0xc7, 0xc9, 
    0x7b, 0x47, 0x78, 0x96, 0xf1, 0x37, 0x0e, 0x88, 
    0xcb, 0xa6, 0x52, 0x29, 0xd7, 0xa8, 0x38, 0x29, 
    0x8e, 0x6e, 0x23, 0x47, 0xd4, 0x4b, 0x70, 0x3e
};
unsigned char brainpool_p512_responder_y_coord[64] = {
    0x80, 0x1f, 0x43, 0xd2, 0x17, 0x35, 0xec, 0x81, 
    0xd9, 0x4b, 0xdc, 0x81, 0x19, 0xd9, 0x5f, 0x68, 
    0x16, 0x84, 0xfe, 0x63, 0x4b, 0x8d, 0x5d, 0xaa, 
    0x88, 0x4a, 0x47, 0x48, 0xd4, 0xea, 0xab, 0x7d, 
    0x6a, 0xbf, 0xe1, 0x28, 0x99, 0x6a, 0x87, 0x1c, 
    0x30, 0xb4, 0x44, 0x2d, 0x75, 0xac, 0x35, 0x09, 
    0x73, 0x24, 0x3d, 0xb4, 0x43, 0xb1, 0xc1, 0x56, 
    0x56, 0xad, 0x30, 0x87, 0xf4, 0xc3, 0x00, 0xc7
};
#endif  /* HAS_BRAINPOOL */


#if 0
unsigned char nist_p256_initiator_x_coord[32] = {
    0x56, 0x26, 0x12, 0xcf, 0x36, 0x48, 0xfe, 0x0b, 
    0x07, 0x04, 0xbb, 0x12, 0x22, 0x50, 0xb2, 0x54, 
    0xb1, 0x94, 0x64, 0x7e, 0x54, 0xce, 0x08, 0x07, 
    0x2e, 0xec, 0xca, 0x74, 0x5b, 0x61, 0x2d, 0x25
};
unsigned char nist_p256_initiator_y_coord[32] = {
    0x3e, 0x44, 0xc7, 0xc9, 0x8c, 0x1c, 0xa1, 0x0b, 
    0x20, 0x09, 0x93, 0xb2, 0xfd, 0xe5, 0x69, 0xdc, 
    0x75, 0xbc, 0xad, 0x33, 0xc1, 0xe7, 0xc6, 0x45, 
    0x4d, 0x10, 0x1e, 0x6a, 0x3d, 0x84, 0x3c, 0xa4
};

unsigned char nist_p256_responder_x_coord[32] = {
    0x1e, 0xa4, 0x8a, 0xb1, 0xa4, 0xe8, 0x42, 0x39, 
    0xad, 0x73, 0x07, 0xf2, 0x34, 0xdf, 0x57, 0x4f, 
    0xc0, 0x9d, 0x54, 0xbe, 0x36, 0x1b, 0x31, 0x0f, 
    0x59, 0x91, 0x52, 0x33, 0xac, 0x19, 0x9d, 0x76
};
unsigned char nist_p256_responder_y_coord[32] = {
    0x26, 0x04, 0x09, 0x45, 0x0a, 0x05, 0x20, 0xe7, 
    0xa7, 0x27, 0xc1, 0x36, 0x76, 0x85, 0xca, 0x3e, 
    0x42, 0x16, 0xf4, 0x89, 0x85, 0x34, 0x6e, 0xd5, 
    0x17, 0xde, 0xc0, 0xb8, 0xad, 0xfd, 0xb2, 0x98
};

unsigned char nist_p384_initiator_x_coord[48] = {
    0x95, 0x3f, 0x42, 0x9e, 0x50, 0x7f, 0xf9, 0xaa, 
    0xac, 0x1a, 0xf2, 0x85, 0x2e, 0x64, 0x91, 0x68, 
    0x64, 0xc4, 0x3c, 0xb7, 0x5c, 0xf8, 0xc9, 0x53, 
    0x6e, 0x58, 0x4c, 0x7f, 0xc4, 0x64, 0x61, 0xac, 
    0x51, 0x8a, 0x6f, 0xfe, 0xab, 0x74, 0xe6, 0x12, 
    0x81, 0xac, 0x38, 0x5d, 0x41, 0xe6, 0xb9, 0xa3
};
unsigned char nist_p384_initiator_y_coord[48] = {
    0x89, 0xd0, 0x97, 0x7b, 0x59, 0x4f, 0xa6, 0xd6, 
    0x7c, 0x5d, 0x93, 0x5b, 0x93, 0xc4, 0x07, 0xa9, 
    0x89, 0xee, 0xd5, 0xcd, 0x6f, 0x42, 0xf8, 0x38, 
    0xc8, 0xc6, 0x62, 0x24, 0x69, 0x0c, 0xd4, 0x48, 
    0xd8, 0x44, 0xd6, 0xc2, 0xe8, 0xcc, 0x62, 0x6b, 
    0x3c, 0x25, 0x53, 0xba, 0x4f, 0x71, 0xf8, 0xe7
};

unsigned char nist_p384_responder_x_coord[48] = {
    0xad, 0xbe, 0xd7, 0x1d, 0x3a, 0x71, 0x64, 0x98, 
    0x5f, 0xb4, 0xd6, 0x4b, 0x50, 0xd0, 0x84, 0x97, 
    0x4b, 0x7e, 0x57, 0x70, 0xd2, 0xd9, 0xf4, 0x92, 
    0x2a, 0x3f, 0xce, 0x99, 0xc5, 0x77, 0x33, 0x44, 
    0x14, 0x56, 0x92, 0xcb, 0xae, 0x46, 0x64, 0xdf, 
    0xe0, 0xbb, 0xd7, 0xb1, 0x29, 0x20, 0x72, 0xdf
};
unsigned char nist_p384_responder_y_coord[48] = {
    0x54, 0x58, 0x20, 0xad, 0x55, 0x1d, 0xca, 0xf3, 
    0x1c, 0x8a, 0xcd, 0x19, 0x40, 0xf9, 0x37, 0x83, 
    0xc7, 0xd6, 0xb3, 0x13, 0x7d, 0x53, 0x28, 0x5c, 
    0xf6, 0x2d, 0xf1, 0xdd, 0xa5, 0x8b, 0xad, 0x5d, 
    0x81, 0xab, 0xb1, 0x00, 0x39, 0xd6, 0xcc, 0x9c, 
    0xea, 0x1e, 0x84, 0x1d, 0xbf, 0xe3, 0x35, 0xf9
};

unsigned char nist_p521_initiator_x_coord[66] = {
    0x00, 0x16, 0x20, 0x45, 0x19, 0x50, 0x95, 0x23, 
    0x0d, 0x24, 0xbe, 0x00, 0x87, 0xdc, 0xfa, 0xf0, 
    0x58, 0x9a, 0x01, 0x60, 0x07, 0x7a, 0xca, 0x76, 
    0x01, 0xab, 0x2d, 0x5a, 0x46, 0xcd, 0x2c, 0xb5, 
    0x11, 0x9a, 0xff, 0xaa, 0x48, 0x04, 0x91, 0x38, 
    0xcf, 0x86, 0xfc, 0xa4, 0xa5, 0x0f, 0x47, 0x01, 
    0x80, 0x1b, 0x30, 0xa3, 0xae, 0xe8, 0x1c, 0x2e, 
    0xea, 0xcc, 0xf0, 0x03, 0x9f, 0x77, 0x4c, 0x8d, 
    0x97, 0x76
};
unsigned char nist_p521_initiator_y_coord[66] = {
    0x01, 0x4c, 0x71, 0xfd, 0x1b, 0xd5, 0x9c, 0xa6, 
    0xed, 0x39, 0xef, 0x45, 0xc5, 0x06, 0xfd, 0x66, 
    0xc0, 0xeb, 0x0f, 0xbf, 0x21, 0xa3, 0x36, 0x74, 
    0xfd, 0xaa, 0x05, 0x6e, 0x4e, 0x33, 0x95, 0x42, 
    0x1a, 0x9d, 0x3f, 0x3a, 0x1c, 0x5e, 0xa8, 0x60, 
    0xf7, 0xe5, 0x59, 0x1d, 0x07, 0xaa, 0x6f, 0x40, 
    0x0a, 0x59, 0x3c, 0x27, 0xad, 0xe0, 0x48, 0xfd, 
    0xd1, 0x83, 0x37, 0x4c, 0xdf, 0xe1, 0x86, 0x72, 
    0xfc, 0x57
};

unsigned char nist_p521_responder_x_coord[66] = {
    0x00, 0x79, 0xe4, 0x4d, 0x6b, 0x5e, 0x12, 0x0a, 
    0x18, 0x2c, 0xb3, 0x05, 0x77, 0x0f, 0xc3, 0x44, 
    0x1a, 0xcd, 0x78, 0x46, 0x14, 0xee, 0x46, 0x3f, 
    0xab, 0xc9, 0x59, 0x7c, 0x85, 0xa0, 0xc2, 0xfb, 
    0x02, 0x32, 0x99, 0xde, 0x5d, 0xe1, 0x0d, 0x48, 
    0x2d, 0x71, 0x7d, 0x8d, 0x3f, 0x61, 0x67, 0x9e, 
    0x2b, 0x8b, 0x12, 0xde, 0x10, 0x21, 0x55, 0x0a, 
    0x5b, 0x2d, 0xe8, 0x05, 0x09, 0xf6, 0x20, 0x97, 
    0x84, 0xb4
};
unsigned char nist_p521_responder_y_coord[66] = {
    0x01, 0xb9, 0x9c, 0xc6, 0x41, 0x32, 0x5b, 0xd2, 
    0x35, 0xd8, 0x8b, 0x2b, 0xe4, 0x6e, 0xcc, 0xdf, 
    0x7c, 0x38, 0xc4, 0x5b, 0xf6, 0x74, 0x71, 0x5c, 
    0x77, 0x16, 0x8a, 0x80, 0xa9, 0x84, 0xc7, 0x7b, 
    0x9d, 0xfd, 0x83, 0x6f, 0xae, 0xf8, 0x24, 0x16, 
    0x2f, 0x21, 0x25, 0x65, 0xa2, 0x1a, 0x6b, 0x2d, 
    0x30, 0x62, 0xb3, 0xcc, 0x6e, 0x59, 0x3c, 0x7f, 
    0x58, 0x91, 0x81, 0x72, 0x07, 0x8c, 0x91, 0xac, 
    0x31, 0x1e
};

#ifdef HAS_BRAINPOOL
unsigned char brainpool_p256_initiator_x_coord[32] = {
    0x46, 0x98, 0x18, 0x6c, 0x27, 0xcd, 0x4b, 0x10, 
    0x7d, 0x55, 0xa3, 0xdd, 0x89, 0x1f, 0x9f, 0xca, 
    0xc7, 0x42, 0x5b, 0x8a, 0x23, 0xed, 0xf8, 0x75, 
    0xac, 0xc7, 0xe9, 0x8d, 0xc2, 0x6f, 0xec, 0xd8
};
unsigned char brainpool_p256_initiator_y_coord[32] = {
    0x16, 0x30, 0x68, 0x32, 0x3b, 0xb0, 0x21, 0xee, 
    0xeb, 0xf7, 0xb6, 0x7c, 0xae, 0x52, 0x26, 0x42, 
    0x59, 0x28, 0x58, 0xb6, 0x14, 0x90, 0xed, 0x69, 
    0xd0, 0x67, 0xea, 0x25, 0x60, 0x0f, 0xa9, 0x6c
};

unsigned char brainpool_p256_responder_x_coord[32] = {
    0x90, 0x18, 0x84, 0xc9, 0xdc, 0xcc, 0xb5, 0x2f, 
    0x4a, 0x3f, 0x4f, 0x18, 0x0a, 0x22, 0x56, 0x6a, 
    0xa9, 0xef, 0xd4, 0xe6, 0xc3, 0x53, 0xc2, 0x1a, 
    0x23, 0x54, 0xdd, 0x08, 0x7e, 0x10, 0xd8, 0xe3
};
unsigned char brainpool_p256_responder_y_coord[32] = {
    0x2a, 0xfa, 0x98, 0x9b, 0xe3, 0xda, 0x30, 0xfd, 
    0x32, 0x28, 0xcb, 0x66, 0xfb, 0x40, 0x7f, 0xf2, 
    0xb2, 0x25, 0x80, 0x82, 0x44, 0x85, 0x13, 0x7e, 
    0x4b, 0xb5, 0x06, 0xc0, 0x03, 0x69, 0x23, 0x64
};

unsigned char brainpool_p384_initiator_x_coord[48] = {
    0x0a, 0x2c, 0xeb, 0x49, 0x5e, 0xb7, 0x23, 0xbd, 
    0x20, 0x5b, 0xe0, 0x49, 0xdf, 0xcf, 0xcf, 0x19, 
    0x37, 0x36, 0xe1, 0x2f, 0x59, 0xdb, 0x07, 0x06, 
    0xb5, 0xeb, 0x2d, 0xae, 0xc2, 0xb2, 0x38, 0x62, 
    0xa6, 0x73, 0x09, 0xa0, 0x6c, 0x0a, 0xa2, 0x30, 
    0x99, 0xeb, 0xf7, 0x1e, 0x47, 0xb9, 0x5e, 0xbe
};
unsigned char brainpool_p384_initiator_y_coord[48] = {
    0x54, 0x76, 0x61, 0x65, 0x75, 0x5a, 0x2f, 0x99, 
    0x39, 0x73, 0xca, 0x6c, 0xf9, 0xf7, 0x12, 0x86, 
    0x54, 0xd5, 0xd4, 0xad, 0x45, 0x7b, 0xbf, 0x32, 
    0xee, 0x62, 0x8b, 0x9f, 0x52, 0xe8, 0xa0, 0xc9, 
    0xb7, 0x9d, 0xd1, 0x09, 0xb4, 0x79, 0x1c, 0x3e, 
    0x1a, 0xbf, 0x21, 0x45, 0x66, 0x6b, 0x02, 0x52
};

unsigned char brainpool_p384_responder_x_coord[48] = {
    0x03, 0xa2, 0x57, 0xef, 0xe8, 0x51, 0x21, 0xa0, 
    0xc8, 0x9e, 0x21, 0x02, 0xb5, 0x9a, 0x36, 0x25, 
    0x74, 0x22, 0xd1, 0xf2, 0x1b, 0xa8, 0x9a, 0x9b, 
    0x97, 0xbc, 0x5a, 0xeb, 0x26, 0x15, 0x09, 0x71, 
    0x77, 0x59, 0xec, 0x8b, 0xb7, 0xe1, 0xe8, 0xce, 
    0x65, 0xb8, 0xaf, 0xf8, 0x80, 0xae, 0x74, 0x6c
};
unsigned char brainpool_p384_responder_y_coord[48] = {
    0x2f, 0xd9, 0x6a, 0xc7, 0x3e, 0xec, 0x76, 0x65, 
    0x2d, 0x38, 0x7f, 0xec, 0x63, 0x26, 0x3f, 0x04, 
    0xd8, 0x4e, 0xff, 0xe1, 0x0a, 0x51, 0x74, 0x70, 
    0xe5, 0x46, 0x63, 0x7f, 0x5c, 0xc0, 0xd1, 0x7c, 
    0xfb, 0x2f, 0xea, 0xe2, 0xd8, 0x0f, 0x84, 0xcb, 
    0xe9, 0x39, 0x5c, 0x64, 0xfe, 0xcb, 0x2f, 0xf1
};

unsigned char brainpool_p512_initiator_x_coord[64] = {
    0x4c, 0xe9, 0xb6, 0x1c, 0xe2, 0x00, 0x3c, 0x9c, 
    0xa9, 0xc8, 0x56, 0x52, 0xaf, 0x87, 0x3e, 0x51, 
    0x9c, 0xbb, 0x15, 0x31, 0x1e, 0xc1, 0x05, 0xfc, 
    0x7c, 0x77, 0xd7, 0x37, 0x61, 0x27, 0xd0, 0x95, 
    0x98, 0xee, 0x5d, 0xa4, 0x3d, 0x09, 0xdb, 0x3d, 
    0xfa, 0x89, 0x9e, 0x7f, 0xa6, 0xa6, 0x9c, 0xff, 
    0x83, 0x5c, 0x21, 0x6c, 0x3e, 0xf2, 0xfe, 0xdc, 
    0x63, 0xe4, 0xd1, 0x0e, 0x75, 0x45, 0x69, 0x0f
};
unsigned char brainpool_p512_initiator_y_coord[64] = {
    0x5a, 0x28, 0x01, 0xbe, 0x96, 0x82, 0x4e, 0xf6, 
    0xfa, 0xed, 0x7d, 0xfd, 0x48, 0x8b, 0x48, 0x4e, 
    0xd1, 0x97, 0x87, 0xc4, 0x05, 0x5d, 0x15, 0x2a, 
    0xf4, 0x91, 0x4b, 0x75, 0x90, 0xd9, 0x34, 0x2c, 
    0x3c, 0x12, 0xf2, 0xf5, 0x25, 0x94, 0x24, 0x34, 
    0xa7, 0x6d, 0x66, 0xbc, 0x27, 0xa4, 0xa0, 0x8d, 
    0xd5, 0xe1, 0x54, 0xa3, 0x55, 0x26, 0xd4, 0x14, 
    0x17, 0x0f, 0xc1, 0xc7, 0x3d, 0x68, 0x7f, 0x5a
};

unsigned char brainpool_p512_responder_x_coord[64] = {
    0x2a, 0x60, 0x32, 0x27, 0xa1, 0xe6, 0x94, 0x72, 
    0x1c, 0x48, 0xbe, 0xc5, 0x77, 0x14, 0x30, 0x76, 
    0xe4, 0xbf, 0xf7, 0x7b, 0xc5, 0xfd, 0xdf, 0x19, 
    0x1e, 0x0f, 0xdf, 0x1c, 0x40, 0xfa, 0x34, 0x9e, 
    0x1f, 0x42, 0x24, 0xa3, 0x2c, 0xd5, 0xc7, 0xc9, 
    0x7b, 0x47, 0x78, 0x96, 0xf1, 0x37, 0x0e, 0x88, 
    0xcb, 0xa6, 0x52, 0x29, 0xd7, 0xa8, 0x38, 0x29, 
    0x8e, 0x6e, 0x23, 0x47, 0xd4, 0x4b, 0x70, 0x3e
};
unsigned char brainpool_p512_responder_y_coord[64] = {
    0x2a, 0xbe, 0x59, 0xe6, 0xc4, 0xb3, 0xd8, 0x09, 
    0x66, 0x89, 0x0a, 0x2d, 0x19, 0xf0, 0x9c, 0x9f, 
    0xb4, 0xab, 0x8f, 0x50, 0x68, 0x3c, 0x74, 0x64, 
    0x4e, 0x19, 0x55, 0x81, 0x9b, 0x48, 0x5c, 0xf4, 
    0x12, 0x8d, 0xb9, 0xd8, 0x02, 0x5b, 0xe1, 0x26, 
    0x7e, 0x19, 0x5c, 0xfd, 0x70, 0xf7, 0x4b, 0xdc, 
    0xb5, 0x5d, 0xc1, 0x7a, 0xe9, 0xd1, 0x05, 0x2e, 
    0xd1, 0xfd, 0x2f, 0xce, 0x63, 0x77, 0x48, 0x2c
};
#endif  /* HAS_BRAINPOOL */
#endif  /* 0 */

//----------------------------------------------------------------------
// debugging routines
//----------------------------------------------------------------------

static void
dpp_debug (int level, const char *fmt, ...)
{
    va_list argptr;

    if (debug & level) {
        va_start(argptr, fmt);
        vprintf(fmt, argptr);
        va_end(argptr);
    }
}

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
print_buffer (int level, char *str, unsigned char *buf, int len)
{
    if (debug & level) {
        printf("%s:\n", str);
        dump_buffer(buf, len);
        printf("\n");
    }
}

static void
pp_a_bignum (int level, char *str, BIGNUM *bn)
{
    unsigned char *buf;
    int len;

    if (debug & level) {
        
        len = BN_num_bytes(bn);
        if ((buf = malloc(len)) == NULL) {
            return;
        }
        BN_bn2bin(bn, buf);
        print_buffer(level, str, buf, len);
        free(buf);
    }
}

static void
pp_a_point (int level, int dotx, char *str, EC_POINT *pt)
{
    BIGNUM *x = NULL, *y = NULL;

    if (debug & level) {
        if (((x = BN_new()) == NULL) ||
            ((y = BN_new()) == NULL)) {
            printf("can't print EC_POINT for '%s', no bignum\n", str);
            goto fail;
        }
        if (!EC_POINT_get_affine_coordinates_GFp(pkex_instance.group, pt, x, y, bnctx)) {
            printf("can't print EC_POINT for '%s', can't get x\n", str);
            goto fail;
        }
        if (dotx) {
            pp_a_bignum(level, str, x);
        } else {
            dpp_debug(level, "%s\n", str);
            pp_a_bignum(level, ".x", x);
            pp_a_bignum(level, ".y", y);
        }
    }

fail:
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
    return;
}

//----------------------------------------------------------------------
// common routines for initiator and responder
//----------------------------------------------------------------------

static int
save_bootstrap_key (struct pkex_peer *peer)
{
    BIO *bio = NULL;
    FILE *fp = NULL;
    unsigned char *ptr, mac[2*ETH_ALEN];
    char newone[1024], existing[1024];
    int ret = -1, len, octets, opclass, channel;
    
    /*
     * get the base64 encoded EC_KEY as onerow[1]
     */
    if (((fp = fopen(pkex_instance.bsfile, "r+")) == NULL) ||
        ((bio = BIO_new(BIO_s_mem())) == NULL)) {
        fprintf(stderr, "PKEX: unable to create BIOs to store %s as bootstrapping file\n", pkex_instance.bsfile);
        goto fin;
    }
    (void)i2d_EC_PUBKEY_bio(bio, peer->peer_bootstrap);
    (void)BIO_flush(bio);
    len = BIO_get_mem_data(bio, &ptr);
    octets = EVP_EncodeBlock((unsigned char *)newone, ptr, len);
    newone[octets] = '\0';
    ret = 0;
    print_buffer(DPP_DEBUG_TRACE, "peer's bootstrap key", (unsigned char *)newone, octets);
    while (!feof(fp)) {
        if (fscanf(fp, "%d %d %d %s %s", &ret, &opclass, &channel, mac, existing) < 0) {
            continue;
        }
//        if (strcmp(existing, newone) == 0) {
//            fprintf(stderr, "PKEX: bootstrapping key is trusted already\n");
//            goto fin;
//        }
    }
    ret++;
    /*
     * bootstrapping file is index opclass channel macaddr key
     */
    fprintf(fp, "%d %d %d %02x%02x%02x%02x%02x%02x %s\n", ret,
            pkex_instance.opclass, pkex_instance.channel,
            peer->peermac[0], peer->peermac[1], peer->peermac[2], 
            peer->peermac[3], peer->peermac[4], peer->peermac[5], 
            newone);
  fin:
    if (bio != NULL) {
        BIO_free(bio);
    }
    if (fp != NULL) {
        fclose(fp);
    }
    return ret;
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

static void
construct_pkex_frame (pkex_frame *frame, struct pkex_peer *peer, unsigned char msg)
{
    memcpy(frame->oui_type, wfa_dpp, sizeof(wfa_dpp));
    frame->cipher_suite = 1;
    frame->frame_type = msg;
    return;
}

static int
send_pkex_frame (unsigned char *mymac, unsigned char *peermac, unsigned char *buf, int len)
{
//    dpp_debug(DPP_DEBUG_ANY, "sending a %d byte frame, and the attributes are %d bytes (%04x)\n",
//              len, attrlen, frame->dpp_attribute_len);
    return transmit_pkex_frame(mymac, peermac, buf, len);
}

static int
find_fixed_elements (int is_initiator)
{
    BIGNUM *xme = NULL, *yme = NULL, *xpeer = NULL, *ypeer = NULL;
    
    if (((xme = BN_new()) == NULL) || ((yme = BN_new()) == NULL) ||
        ((xpeer = BN_new()) == NULL) || ((ypeer = BN_new()) == NULL)) {
        goto fin;
    }

    if (is_initiator) {
        switch (pkex_instance.group_num) {
            case 19:
                BN_bin2bn(nist_p256_initiator_x_coord, 32, xme);
                BN_bin2bn(nist_p256_initiator_y_coord, 32, yme);
                BN_bin2bn(nist_p256_responder_x_coord, 32, xpeer);
                BN_bin2bn(nist_p256_responder_y_coord, 32, ypeer);
                break;
            case 20:
                BN_bin2bn(nist_p384_initiator_x_coord, 48, xme);
                BN_bin2bn(nist_p384_initiator_y_coord, 48, yme);
                BN_bin2bn(nist_p384_responder_x_coord, 48, xpeer);
                BN_bin2bn(nist_p384_responder_y_coord, 48, ypeer);
                break;
            case 21:
                BN_bin2bn(nist_p521_initiator_x_coord, 66, xme);
                BN_bin2bn(nist_p521_initiator_y_coord, 66, yme);
                BN_bin2bn(nist_p521_responder_x_coord, 66, xpeer);
                BN_bin2bn(nist_p521_responder_y_coord, 66, ypeer);
                break;
#ifdef HAS_BRAINPOOL
            case 28:
                BN_bin2bn(brainpool_p256_initiator_x_coord, 32, xme);
                BN_bin2bn(brainpool_p256_initiator_y_coord, 32, yme);
                BN_bin2bn(brainpool_p256_responder_x_coord, 32, xpeer);
                BN_bin2bn(brainpool_p256_responder_y_coord, 32, ypeer);
                break;
            case 29:
                BN_bin2bn(brainpool_p384_initiator_x_coord, 48, xme);
                BN_bin2bn(brainpool_p384_initiator_y_coord, 48, yme);
                BN_bin2bn(brainpool_p384_responder_x_coord, 48, xpeer);
                BN_bin2bn(brainpool_p384_responder_y_coord, 48, ypeer);
                break;
            case 30:
                BN_bin2bn(brainpool_p512_initiator_x_coord, 64, xme);
                BN_bin2bn(brainpool_p512_initiator_y_coord, 64, yme);
                BN_bin2bn(brainpool_p512_responder_x_coord, 64, xpeer);
                BN_bin2bn(brainpool_p512_responder_y_coord, 64, ypeer);
                break;
#endif  /* HAS_BRAINPOOL */
            default:
                break;
        }
    } else {
        switch (pkex_instance.group_num) {
            case 19:
                BN_bin2bn(nist_p256_initiator_x_coord, 32, xpeer);
                BN_bin2bn(nist_p256_initiator_y_coord, 32, ypeer);
                BN_bin2bn(nist_p256_responder_x_coord, 32, xme);
                BN_bin2bn(nist_p256_responder_y_coord, 32, yme);
                break;
            case 20:
                BN_bin2bn(nist_p384_initiator_x_coord, 48, xpeer);
                BN_bin2bn(nist_p384_initiator_y_coord, 48, ypeer);
                BN_bin2bn(nist_p384_responder_x_coord, 48, xme);
                BN_bin2bn(nist_p384_responder_y_coord, 48, yme);
                break;
            case 21:
                BN_bin2bn(nist_p521_initiator_x_coord, 66, xpeer);
                BN_bin2bn(nist_p521_initiator_y_coord, 66, ypeer);
                BN_bin2bn(nist_p521_responder_x_coord, 66, xme);
                BN_bin2bn(nist_p521_responder_y_coord, 66, yme);
                break;
#ifdef HAS_BRAINPOOL
            case 28:
                BN_bin2bn(brainpool_p256_initiator_x_coord, 32, xpeer);
                BN_bin2bn(brainpool_p256_initiator_y_coord, 32, ypeer);
                BN_bin2bn(brainpool_p256_responder_x_coord, 32, xme);
                BN_bin2bn(brainpool_p256_responder_y_coord, 32, yme);
                break;
            case 29:
                BN_bin2bn(brainpool_p384_initiator_x_coord, 48, xpeer);
                BN_bin2bn(brainpool_p384_initiator_y_coord, 48, ypeer);
                BN_bin2bn(brainpool_p384_responder_x_coord, 48, xme);
                BN_bin2bn(brainpool_p384_responder_y_coord, 48, yme);
                break;
            case 30:
                BN_bin2bn(brainpool_p512_initiator_x_coord, 64, xpeer);
                BN_bin2bn(brainpool_p512_initiator_y_coord, 64, ypeer);
                BN_bin2bn(brainpool_p512_responder_x_coord, 64, xme);
                BN_bin2bn(brainpool_p512_responder_y_coord, 64, yme);
                break;
#endif  /* HAS_BRAINPOOL */
            default:
                break;
        }
    }
    if ((pkex_instance.Pme = EC_POINT_new(pkex_instance.group)) == NULL) {
        goto fin;
    }
    if (!EC_POINT_set_affine_coordinates_GFp(pkex_instance.group,
                                             pkex_instance.Pme, xme, yme, bnctx)) {
        EC_POINT_free(pkex_instance.Pme);
        goto fin;
    }
    if (!EC_POINT_is_on_curve(pkex_instance.group, pkex_instance.Pme, bnctx)) {
        EC_POINT_free(pkex_instance.Pme);
        goto fin;
    }
        
    if ((pkex_instance.Ppeer = EC_POINT_new(pkex_instance.group)) == NULL) {
        EC_POINT_free(pkex_instance.Pme);
        goto fin;
    }
    if (!EC_POINT_set_affine_coordinates_GFp(pkex_instance.group,
                                             pkex_instance.Ppeer, xpeer, ypeer, bnctx)) {
        EC_POINT_free(pkex_instance.Pme);
        EC_POINT_free(pkex_instance.Ppeer);
        goto fin;
    }
    if (!EC_POINT_is_on_curve(pkex_instance.group, pkex_instance.Ppeer, bnctx)) {
        EC_POINT_free(pkex_instance.Pme);
        EC_POINT_free(pkex_instance.Ppeer);
        goto fin;
    }
fin:
    if (xme != NULL) {
        BN_free(xme);
    }
    if (yme != NULL) {
        BN_free(yme);
    }
    if (xpeer != NULL) {
        BN_free(xpeer);
    }
    if (ypeer != NULL) {
        BN_free(ypeer);
    }
    
    return ((pkex_instance.Pme != NULL) && (pkex_instance.Ppeer != NULL));
}

static int
compute_z (struct pkex_peer *peer)
{
    int ret = -1, offset;
    unsigned char *ptr, *context = NULL, *ikm = NULL;
    BIGNUM *x = NULL, *y = NULL;
    EC_POINT *Z = NULL;
    const BIGNUM *ephem = NULL;

    if (((Z = EC_POINT_new(pkex_instance.group)) == NULL) ||
        ((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
        ((ephem = EC_KEY_get0_private_key(peer->X)) == NULL) ||
        !EC_POINT_mul(pkex_instance.group, Z, NULL, peer->Y, ephem, bnctx) ||
        !EC_POINT_get_affine_coordinates_GFp(pkex_instance.group, Z, x, NULL, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to compute Z!\n");
        goto fin;
    }
    pp_a_bignum(DPP_DEBUG_TRACE, peer->initiator ? "x" : "y", (BIGNUM *)ephem);
    pp_a_point(DPP_DEBUG_TRACE, 1, peer->initiator ? "Y.x" : "X.x", peer->Y);
    
    if (((context = (unsigned char *)malloc(2 * pkex_instance.primelen + 2 * ETH_ALEN +
                                            strlen(pkex_instance.password))) == NULL) ||
        ((ikm = (unsigned char *)malloc(pkex_instance.primelen)) == NULL)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to allocate context for HKDF!\n");
        goto fin;
    }

    /*
     * the input key to the kdf is Z.x where Z = x*Y
     */
    memset(ikm, 0, pkex_instance.primelen);
    offset = pkex_instance.primelen - BN_num_bytes(x);
    BN_bn2bin(x, ikm + offset);
    pp_a_bignum(DPP_DEBUG_TRACE, peer->initiator ? "Z.x = (x*Y).x" : "Z.x = (y*X).x", x);

    memset(context, 0, 2 * pkex_instance.primelen + 2 * ETH_ALEN + strlen(pkex_instance.password));
    ptr = context;
    /*
     * the context is the initiator mac address followed by the responder mac address...
     */
    dpp_debug(DPP_DEBUG_TRACE, "context to create z\n");
    if (peer->initiator) {
        print_buffer(DPP_DEBUG_TRACE, "MAC-Initiator", peer->mymac, ETH_ALEN);
        memcpy(ptr, peer->mymac, ETH_ALEN);
        ptr += ETH_ALEN;
        
        print_buffer(DPP_DEBUG_TRACE, "MAC-Responder", peer->peermac, ETH_ALEN);
        memcpy(ptr, peer->peermac, ETH_ALEN);
        ptr += ETH_ALEN;
    } else {
        print_buffer(DPP_DEBUG_TRACE, "MAC-Initiator", peer->peermac, ETH_ALEN);
        memcpy(ptr, peer->peermac, ETH_ALEN);
        ptr += ETH_ALEN;
        
        print_buffer(DPP_DEBUG_TRACE, "MAC-Responder", peer->mymac, ETH_ALEN);
        memcpy(ptr, peer->mymac, ETH_ALEN);
        ptr += ETH_ALEN;
    }
    /*
     * ...concatenated with M.x (or when viewed as responder N.x)
     */
    if (peer->initiator) {
        pp_a_bignum(DPP_DEBUG_TRACE, "M.x", peer->m);
        offset = pkex_instance.primelen - BN_num_bytes(peer->m);
        BN_bn2bin(peer->m, ptr + offset);
    } else {
        pp_a_bignum(DPP_DEBUG_TRACE, "M.x", peer->n);
        offset = pkex_instance.primelen - BN_num_bytes(peer->n);
        BN_bn2bin(peer->n, ptr + offset);
    }
    ptr += pkex_instance.primelen;
    /*
     * ...concatenated with N.x (or when viewed as responder M.x)
     */
    if (peer->initiator) {
        pp_a_bignum(DPP_DEBUG_TRACE, "N.x", peer->n);
        offset = pkex_instance.primelen - BN_num_bytes(peer->n);
        BN_bn2bin(peer->n, ptr + offset);
    } else {
        pp_a_bignum(DPP_DEBUG_TRACE, "N.x", peer->m);
        offset = pkex_instance.primelen - BN_num_bytes(peer->m);
        BN_bn2bin(peer->m, ptr + offset);
    }
    ptr += pkex_instance.primelen;
    /*
     * ...concatenated with the password
     */
    memcpy(ptr, pkex_instance.password, strlen(pkex_instance.password));
    print_buffer(DPP_DEBUG_TRACE, "password", (unsigned char *)pkex_instance.password, strlen(pkex_instance.password));

    hkdf(pkex_instance.hashfcn, 0, ikm, pkex_instance.primelen,
         NULL, 0,
         context, (2 * pkex_instance.primelen + 2 * ETH_ALEN + strlen(pkex_instance.password)),
         peer->z, pkex_instance.digestlen);

    ret = 1;
    print_buffer(DPP_DEBUG_TRACE, "z", peer->z, pkex_instance.digestlen);
    
fin:
    if (context != NULL) {
        free(context);
    }
    if (ikm != NULL) {
        free(ikm);
    }
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
    if (Z != NULL) {
        EC_POINT_free(Z);
    }
    return ret;
}

//----------------------------------------------------------------------
// transmitting routines for initiator and responder
//----------------------------------------------------------------------

int
pkex_reveal_to_peer (struct pkex_peer *peer) 
{
    unsigned char buf[1024], *ptr, *keyx = NULL, *ikm = NULL, direction;
    pkex_frame *frame;
    int ret = -1, offset, datalen = 0;
    unsigned int mdlen = pkex_instance.digestlen;
    const BIGNUM *priv;
    const EC_POINT *Pub, *Xpt;
    BIGNUM *s = NULL, *x = NULL, *y = NULL;
    EC_POINT *S = NULL;
    HMAC_CTX *hctx = NULL;
    TLV *tlv;
    siv_ctx ctx;

    memset(buf, 0, sizeof(buf));
    frame = (pkex_frame *)buf;
    construct_pkex_frame(frame, peer, peer->initiator ? PKEX_SUB_COM_REV_REQ : PKEX_SUB_COM_REV_RESP);

    if (((s = BN_new()) == NULL) || ((S = EC_POINT_new(pkex_instance.group)) == NULL) ||
        ((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
        ((hctx = HMAC_CTX_new()) == NULL) ||
        ((Pub = EC_KEY_get0_public_key(pkex_instance.bootstrap)) == NULL) ||
        ((priv = EC_KEY_get0_private_key(pkex_instance.bootstrap)) == NULL)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to get private key from bootstrapped key\n");
        goto fin;
    }
    if (((ikm = (unsigned char *)malloc(pkex_instance.primelen)) == NULL) ||
        ((keyx = (unsigned char *)malloc(pkex_instance.primelen)) == NULL)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to malloc context to create confirm\n");
        goto fin;
    }
    /*
     * S = x * Y
     */
    if (!EC_POINT_mul(pkex_instance.group, S, NULL, peer->Y, priv, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "can't determine shared PKEX secret, S\n");
        goto fin;
    }
    /*
     * x = F(S) which becomes ikm...
     */
    if (!EC_POINT_get_affine_coordinates_GFp(pkex_instance.group, S, x, NULL, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "can't get shared PKEX secret, s\n");
        goto fin;
    }
    pp_a_bignum(DPP_DEBUG_TRACE, peer->initiator ? "(a*Y).x" : "(b*X).x", x);
    /*
     * ...the key used for our committing tag
     */
    memset(ikm, 0, pkex_instance.primelen);
    offset = pkex_instance.primelen - BN_num_bytes(x);
    BN_bn2bin(x, ikm + offset);

    /*
     * construct the frame, it's wrapped data...
     * (AES_BLOCK_SIZE is part of the length to include the SIV)
     */
    tlv = (TLV *)frame->attributes;
    tlv->type = WRAPPED_DATA;
    tlv->length = ieee_order(AES_BLOCK_SIZE + sizeof(TLV) + 2 * pkex_instance.primelen +
                             sizeof(TLV) + pkex_instance.digestlen);
    ptr = tlv->value;
    /*
     * first inside the wrapped data is my bootstrapping key
     */
    tlv = (TLV *)(ptr + AES_BLOCK_SIZE); // ptr is where the SIV goes
    tlv->type = BOOTSTRAP_KEY;
    tlv->length = 2 * pkex_instance.primelen;
    ptr = tlv->value;
    
    if (!EC_POINT_get_affine_coordinates_GFp(pkex_instance.group, Pub, x, y, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "can't get shared PKEX secret, s\n");
        goto fin;
    }
    offset = pkex_instance.primelen - BN_num_bytes(x);
    BN_bn2bin(x, ptr + offset);
    ptr += pkex_instance.primelen;
    offset = pkex_instance.primelen - BN_num_bytes(y);
    BN_bn2bin(y, ptr + offset);
    ptr += pkex_instance.primelen;

    /*
     * next is our committing tag... 
     */
    tlv = TLV_next(tlv);
    tlv->type = peer->initiator ? INITIATOR_AUTH_TAG : RESPONDER_AUTH_TAG;
    tlv->length = pkex_instance.digestlen;
    /*
     * "sign" our binding context using the input-keying-material, ikm
     */
    HMAC_Init_ex(hctx, ikm, pkex_instance.primelen, pkex_instance.hashfcn, NULL);
    /*
     * ...first it's my MAC address
     */
    dpp_debug(DPP_DEBUG_TRACE, peer->initiator ? "context for u\n" : "context for v\n");
    print_buffer(DPP_DEBUG_TRACE, peer->initiator ? "MAC-Initiator" : "MAC-Responder",
                 peer->mymac, ETH_ALEN);
    HMAC_Update(hctx, peer->mymac, ETH_ALEN);
    
    /*
     * followed by my bootstrapping key 
     */
    if (!EC_POINT_get_affine_coordinates_GFp(pkex_instance.group, Pub, x, NULL, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "can't get shared PKEX secret, s\n");
        goto fin;
    }
    pp_a_bignum(DPP_DEBUG_TRACE, peer->initiator ? "A.x" : "B.x", x);
    offset = pkex_instance.primelen - BN_num_bytes(x);
    memset(keyx, 0, pkex_instance.primelen);
    BN_bn2bin(x, keyx + offset);
    HMAC_Update(hctx, keyx, pkex_instance.primelen);
    
    /*
     * followed by the peer's ephemeral key
     */
    if (!EC_POINT_get_affine_coordinates_GFp(pkex_instance.group, peer->Y, x, NULL, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "can't get shared PKEX secret, s\n");
        goto fin;
    }
    pp_a_bignum(DPP_DEBUG_TRACE, peer->initiator ? "Y.x" : "X.x", x);
    offset = pkex_instance.primelen - BN_num_bytes(x);
    memset(keyx, 0, pkex_instance.primelen);
    BN_bn2bin(x, keyx + offset);
    HMAC_Update(hctx, keyx, pkex_instance.primelen);

    /*
     * followed by my ephermal key
     */
    if (((Xpt = EC_KEY_get0_public_key(peer->X)) == NULL) ||
        !EC_POINT_get_affine_coordinates_GFp(pkex_instance.group, Xpt, x, NULL, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to construct authenticating tag (X)!\n");
        goto fin;
    }
    pp_a_bignum(DPP_DEBUG_TRACE, peer->initiator ? "X.x" : "Y.x", x);
    offset = pkex_instance.primelen - BN_num_bytes(x);
    memset(keyx, 0, pkex_instance.primelen);
    BN_bn2bin(x, keyx + offset);
    HMAC_Update(hctx, keyx, pkex_instance.primelen);

    HMAC_Final(hctx, tlv->value, &mdlen);
    print_buffer(DPP_DEBUG_TRACE, peer->initiator ? "u" : "v", tlv->value, mdlen);
    ptr = tlv->value + mdlen;
    
    switch (pkex_instance.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, peer->z, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, peer->z, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, peer->z, SIV_512);
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", pkex_instance.digestlen);
            goto fin;
    }
    datalen = (int)(ptr - (frame->attributes + sizeof(TLV) + AES_BLOCK_SIZE));
    tlv = (TLV *)frame->attributes;
    ptr = TLV_value(tlv);
    /*
     * ieee-ize the TLVs that get wrapped, wrap them, using "direction" as AAD
     */
    direction = peer->initiator ? 0 : 1;
    ieee_ize_attributes(ptr + AES_BLOCK_SIZE, datalen);
    siv_encrypt(&ctx, ptr + AES_BLOCK_SIZE, ptr + AES_BLOCK_SIZE, datalen, ptr,
                2, frame, sizeof(pkex_frame), &direction, 1);

    dpp_debug(DPP_DEBUG_PROTOCOL_MSG,
              peer->initiator ? "sending PKEX Commit/Reveal Request\n" : "sending PKEX Commit/Reveal Response\n");
    ret = send_pkex_frame(peer->mymac, peer->peermac, buf,
                          sizeof(pkex_frame) + sizeof(TLV) + datalen + AES_BLOCK_SIZE);
    peer->state = PKEX_SEND_COMREV;
    ret = sizeof(pkex_frame) + datalen + AES_BLOCK_SIZE;
fin:
    if (keyx != NULL) {
        free(keyx);
    }
    if (ikm != NULL) {
        free(ikm);
    }
    if (s != NULL) {
        BN_free(s);
    }
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
    if (S != NULL) {
        EC_POINT_free(S);
    }
    if (hctx != NULL) {
        HMAC_CTX_free(hctx);
    }
    return ret;
}

int
pkex_exchange_to_peer (struct pkex_peer *peer, unsigned char status)
{
    unsigned char *ptr, buf[1024], machash[SHA512_DIGEST_LENGTH];
    unsigned int mdlen = pkex_instance.digestlen;
    pkex_frame *frame = (pkex_frame *)buf;
    unsigned short grp;
    BIGNUM *x = NULL, *y = NULL, *hmul = NULL, *order = NULL;
    TLV *tlv;
    EC_POINT *Q;
    const EC_POINT *Xpt;
    EVP_MD_CTX *mdctx = NULL;
    int offset, framelen, ret = -1;

    memset(buf, 0, sizeof(buf));
    construct_pkex_frame(frame, peer, peer->initiator ? PKEX_SUB_EXCH_REQ : PKEX_SUB_EXCH_RESP);
    tlv = (TLV *)frame->attributes;

    if ((pkex_instance.bootstrap == NULL) || (pkex_instance.group == NULL) || (pkex_instance.group_num == 0)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to send PKEX frame, no bootstrap key!\n");
        goto fin;
    }

    if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
        ((order = BN_new()) == NULL) || ((hmul = BN_new()) == NULL) ||
        ((mdctx = EVP_MD_CTX_new()) == NULL) ||
        ((peer->m = BN_new()) == NULL) || ((Q = EC_POINT_new(pkex_instance.group)) == NULL)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to create key for PKEX\n");
        goto fin;
    }
    /*
     * if we're retransmitting we don't want to generate a new one
     */
    if (peer->X == NULL) {
        if (((peer->X = EC_KEY_new_by_curve_name(pkex_instance.nid)) == NULL) ||
            !EC_KEY_generate_key(peer->X)) {
            dpp_debug(DPP_DEBUG_ERR, "unable to generate key for PKEX!\n");
            goto fin;
        }
    }

    if (!EC_GROUP_get_order(pkex_instance.group, order, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to obtain order from the group! Order! Order!!\n");
        goto fin;
    }
    /*
     * Q = H(me | [identifier |] pw) * P
     */
    EVP_DigestInit(mdctx, pkex_instance.hashfcn);
    EVP_DigestUpdate(mdctx, peer->mymac, ETH_ALEN);
    if (pkex_instance.adds_identifier) {
        EVP_DigestUpdate(mdctx, pkex_instance.identifier, strlen(pkex_instance.identifier));
    }
    EVP_DigestUpdate(mdctx, pkex_instance.password, strlen(pkex_instance.password));
    EVP_DigestFinal(mdctx, machash, &mdlen);
    BN_bin2bn(machash, mdlen, hmul);
    BN_mod(hmul, hmul, order, bnctx);

    if (pkex_instance.adds_identifier) {
        print_buffer(DPP_DEBUG_TRACE, "identifier", (unsigned char *)pkex_instance.identifier,
                     strlen(pkex_instance.identifier));
    }
    print_buffer(DPP_DEBUG_TRACE, "password", (unsigned char *)pkex_instance.password, strlen(pkex_instance.password));
    pp_a_bignum(DPP_DEBUG_TRACE, "H(mymac | [identifier | ] password)", hmul);
    pp_a_point(DPP_DEBUG_TRACE, 1, peer->initiator ? "Pinit.x" : "Presp.x", pkex_instance.Pme);
    
    if (!EC_POINT_mul(pkex_instance.group, Q, NULL, pkex_instance.Pme, hmul, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to create Q for PKEX!\n");
        goto fin;
    }
    pp_a_point(DPP_DEBUG_TRACE, 1, peer->initiator ? "Qi.x" : "Qr.x", Q);

    /*
     * reuse Q so the encrypted point is now Q = X + Q
     */
    if ((Xpt = EC_KEY_get0_public_key(peer->X)) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to get ephemeral key for PKEX!\n");
        goto fin;
    }
    pp_a_point(DPP_DEBUG_TRACE, 1, peer->initiator ? "X.x" : "Y.x", (EC_POINT *)Xpt);
    
    if (!EC_POINT_add(pkex_instance.group, Q, Xpt, Q, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to encrypt pubkey for PKEX!\n");
        goto fin;
    }
    if (!EC_POINT_get_affine_coordinates_GFp(pkex_instance.group, Q, x, y, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to obtain x,y from encrypted key!\n");
        goto fin;
    }
    pp_a_bignum(DPP_DEBUG_TRACE, peer->initiator ? "M.x" : "N.x", x);
    pp_a_bignum(DPP_DEBUG_TRACE, peer->initiator ? "M.y" : "N.y", y);

    /*
     * the encrypted key is M so m = M.x which we need for kdf context later
     */
    BN_copy(peer->m, x);

    /*
     * and start filling in the frame
     */
    framelen = sizeof(pkex_frame);
    if (peer->initiator) {
        /*
         * if the initiator, first add the group...
         */
        grp = ieee_order(pkex_instance.group_num);
        tlv = TLV_set_tlv(tlv, FINITE_CYCLIC_GROUP, sizeof(unsigned short), (unsigned char *)&grp);
        framelen += (sizeof(unsigned short) + sizeof(TLV));
    } else {
        /*
         * otherwise, add the status...
         */
        tlv = TLV_set_tlv(tlv, DPP_STATUS, sizeof(unsigned char), &status);
        framelen += (sizeof(unsigned char) + sizeof(TLV));
    }
    /*
     * ...if we're doing a PKEX identifier too then add that
     */
    if (pkex_instance.adds_identifier) {
        tlv = TLV_set_tlv(tlv, CODE_IDENTIFIER, strlen(pkex_instance.identifier),
                          (unsigned char *)pkex_instance.identifier);
        framelen += (strlen(pkex_instance.identifier) + sizeof(TLV));
    }
    
    /*
     * ... then the encrypted public key
     */
    tlv->type = ENCRYPTED_KEY;
    tlv->length = 2 * pkex_instance.primelen;
    ptr = tlv->value;

    offset = pkex_instance.primelen - BN_num_bytes(x);
    BN_bn2bin(x, ptr + offset);
    ptr += pkex_instance.primelen;
    offset = pkex_instance.primelen - BN_num_bytes(y);
    BN_bn2bin(y, ptr + offset);
    ptr += pkex_instance.primelen;

    framelen += (2 * pkex_instance.primelen + sizeof(TLV));
    tlv = TLV_next(tlv);

    ieee_ize_attributes(frame->attributes, framelen);
    dpp_debug(DPP_DEBUG_PROTOCOL_MSG,
              peer->initiator ? "sending PKEX Exchange Request\n" : "sending PKEX Exchange Response\n");
    ret = send_pkex_frame(peer->mymac, peer->peermac, buf, framelen);
    peer->state = PKEX_SEND_EXCHANGE;
    ret = 1;
fin:
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
    if (mdctx != NULL) {
        EVP_MD_CTX_free(mdctx);
    }
    if (order != NULL) {
        BN_free(order);
    }
    if (hmul != NULL) {
        BN_free(hmul);
    }
    return ret;
}

static void
retransmit_pkex (timerid id, void *data)
{
    struct pkex_peer *peer = (struct pkex_peer *)data;

    dpp_debug(DPP_DEBUG_STATE_MACHINE, "timer %d fired! retransmit %d!\n", peer->t0, peer->retrans);
    if (peer->retrans > 5) {
        dpp_debug(DPP_DEBUG_STATE_MACHINE, "too many retransmits...bailing!\n");
        return;
    }
    switch (peer->state) {
        case PKEX_SEND_EXCHANGE:
            pkex_exchange_to_peer(peer, STATUS_OK);
            peer->t0 = srv_add_timeout(srvctx, SRV_SEC(2), retransmit_pkex, peer);
            peer->retrans++;
            break;
        case PKEX_SEND_COMREV:
            pkex_reveal_to_peer(peer);
            peer->t0 = srv_add_timeout(srvctx, SRV_SEC(2), retransmit_pkex, peer);
            peer->retrans++;
            break;
        case PKEX_NOTHING:
        case PKEX_FINISHED:
            dpp_debug(DPP_DEBUG_STATE_MACHINE, "timer should not fire in %s\n",
                      state_to_string(peer->state));
            break;
        default:
            dpp_debug(DPP_DEBUG_STATE_MACHINE, "time fired in unknown state (%d)\n",
                      peer->state);
    }
}

//----------------------------------------------------------------------
// receiveing routines for initiator and responder
//----------------------------------------------------------------------

static int
process_pkex_reveal (pkex_frame *frame, int len, struct pkex_peer *peer)
{
    unsigned char *ptr, *keyx = NULL, *ikm = NULL, direction;
    unsigned char tag[SHA512_DIGEST_LENGTH];
    unsigned int mdlen = pkex_instance.digestlen;
    int ret = -1;
    int offset;
    EC_POINT *S = NULL;
    const EC_POINT *A, *Xpt;
    const BIGNUM *priv;
    HMAC_CTX *hctx = NULL;
    BIGNUM *x = NULL, *y = NULL;
    TLV *tlv;
    siv_ctx ctx;

    if ((hctx = HMAC_CTX_new()) == NULL) {
        dpp_debug(DPP_DEBUG_ERR, "unable to create HMAC context!\n");
        goto fin;
    }
    switch (pkex_instance.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, peer->z, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, peer->z, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, peer->z, SIV_512);
            break;
        default:
            dpp_debug(DPP_DEBUG_ERR, "unknown digest length %d!\n", pkex_instance.digestlen);
            goto fin;
    }
    tlv = (TLV *)frame->attributes;
    if (tlv->type != WRAPPED_DATA) {
        dpp_debug(DPP_DEBUG_ERR, "malformed PKEX reveal, no wrapped data!\n");
        goto fin;
    }

    direction = peer->initiator ? 1 : 0;
    if (siv_decrypt(&ctx, TLV_value(tlv) + AES_BLOCK_SIZE, TLV_value(tlv) + AES_BLOCK_SIZE,
                    TLV_length(tlv) - AES_BLOCK_SIZE, TLV_value(tlv), 
                    2, frame, sizeof(pkex_frame), &direction, 1) < 1) {
        dpp_debug(DPP_DEBUG_ANY, "can't unwrap PKEX Commit/Reveal! Password mismatch?\n");
        goto fin;
    }
    ieee_ize_attributes(TLV_value(tlv) + AES_BLOCK_SIZE, TLV_length(tlv) - AES_BLOCK_SIZE);

    if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
        ((S = EC_POINT_new(pkex_instance.group)) == NULL)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to create x,y!\n");
        goto fin;
    }

    if (((keyx = (unsigned char *)malloc(pkex_instance.primelen)) == NULL) ||
        ((ikm = (unsigned char *)malloc(pkex_instance.primelen)) == NULL)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to malloc context to create confirm\n");
        goto fin;
    }

    tlv = (TLV *)(TLV_value(tlv) + AES_BLOCK_SIZE);
    if (TLV_type(tlv) != BOOTSTRAP_KEY) {
        dpp_debug(DPP_DEBUG_ERR, "malformed PKEX reveal, no bootstrap key!\n");
        goto fin;
    }
    
    /*
     * obtain, set, and check the peer's bootstrap key
     */
    ptr = TLV_value(tlv);
    BN_bin2bn(ptr, pkex_instance.primelen, x);
    ptr += pkex_instance.primelen;
    BN_bin2bn(ptr, pkex_instance.primelen, y);
    ptr += pkex_instance.primelen;

    peer->peer_bootstrap = EC_KEY_new_by_curve_name(pkex_instance.nid);
    EC_KEY_set_public_key_affine_coordinates(peer->peer_bootstrap, x, y);
    EC_KEY_set_conv_form(peer->peer_bootstrap, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(peer->peer_bootstrap, OPENSSL_EC_NAMED_CURVE);
    if (((A = EC_KEY_get0_public_key(peer->peer_bootstrap)) == NULL) ||
        !EC_POINT_is_on_curve(pkex_instance.group, A, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "peer bootstrapping key is invalid!\n");
        EC_KEY_free(peer->peer_bootstrap);
        goto fin;
    }

    if (((priv = EC_KEY_get0_private_key(peer->X)) == NULL) ||
        !EC_POINT_mul(pkex_instance.group, S, NULL, A, priv, bnctx) ||
        !EC_POINT_get_affine_coordinates_GFp(pkex_instance.group, S, x, NULL, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to compute kb\n");
        goto fin;
    }
    pp_a_bignum(DPP_DEBUG_TRACE, peer->initiator ? "x" : "y", (BIGNUM *)priv);
    pp_a_point(DPP_DEBUG_TRACE, 1, peer->initiator ? "B" : "A", (EC_POINT *)A);
    pp_a_bignum(DPP_DEBUG_TRACE, peer->initiator ? "(x*B).x" : "(y*A).x", x);
    memset(ikm, 0, pkex_instance.primelen);
    offset = pkex_instance.primelen - BN_num_bytes(x);
    BN_bn2bin(x, ikm + offset);

    /*
     * check the signed committment
     */
    HMAC_Init_ex(hctx, ikm, pkex_instance.primelen, pkex_instance.hashfcn, NULL);
    /*
     * ...first is the peer's mac address
     */
    dpp_debug(DPP_DEBUG_TRACE, peer->initiator? "context for v'\n" : "context for u'\n");
    print_buffer(DPP_DEBUG_TRACE, peer->initiator ? "MAC-Responder" : "MAC-Initiator",
                 peer->peermac, ETH_ALEN);
    HMAC_Update(hctx, peer->peermac, ETH_ALEN);

    /*
     * followed by the peer's bootstrapping key
     */
    if (!EC_POINT_get_affine_coordinates_GFp(pkex_instance.group, A, x, NULL, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "can't get shared PKEX secret, s\n");
        goto fin;
    }
    pp_a_bignum(DPP_DEBUG_TRACE, peer->initiator ? "B.x" : "A.x", x);
    memset(keyx, 0, pkex_instance.primelen);
    offset = pkex_instance.primelen - BN_num_bytes(x);
    BN_bn2bin(x, keyx + offset);
    HMAC_Update(hctx, keyx, pkex_instance.primelen);

    /*
     * ...followed by my ephemeral key
     */
    if (((Xpt = EC_KEY_get0_public_key(peer->X)) == NULL) ||
        !EC_POINT_get_affine_coordinates_GFp(pkex_instance.group, Xpt, x, NULL, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "can't get shared PKEX secret, s\n");
        goto fin;
    }
    pp_a_bignum(DPP_DEBUG_TRACE, peer->initiator ? "X.x" : "Y.x", x);
    memset(keyx, 0, pkex_instance.primelen);
    offset = pkex_instance.primelen - BN_num_bytes(x);
    BN_bn2bin(x, keyx + offset);
    HMAC_Update(hctx, keyx, pkex_instance.primelen);

    /*
     * ...followed by his ephemeral key
     */
    if (!EC_POINT_get_affine_coordinates_GFp(pkex_instance.group, peer->Y, x, NULL, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to construct authenticating tag (Y)!\n");
        goto fin;
    }
    pp_a_bignum(DPP_DEBUG_TRACE, peer->initiator ? "Y'.x" : "X'.x", x);
    memset(keyx, 0, pkex_instance.primelen);
    offset = pkex_instance.primelen - BN_num_bytes(x);
    BN_bn2bin(x, keyx + offset);
    HMAC_Update(hctx, keyx, pkex_instance.primelen);

    HMAC_Final(hctx, tag, &mdlen);
    print_buffer(DPP_DEBUG_TRACE, peer->initiator ? "v'" : "u'", tag, mdlen);

    tlv = TLV_next(tlv);
    if (peer->initiator) {
        if (TLV_type(tlv) != RESPONDER_AUTH_TAG) {
            dpp_debug(DPP_DEBUG_ERR, "malformed PKEX reveal, no responder auth tag!\n");
            goto fin;
        }
    } else {
        if (TLV_type(tlv) != INITIATOR_AUTH_TAG) {
            dpp_debug(DPP_DEBUG_ERR, "malformed PKEX reveal, no initiator auth tag!\n");
            goto fin;
        }
    }
    if (memcmp(tag, TLV_value(tlv), mdlen) == 0) {
        dpp_debug(DPP_DEBUG_ANY, "AUTHENTICATED PEER! Bootstrapping key is trusted!\n\n");
        if ((ret = save_bootstrap_key(peer)) < 1) {
            dpp_debug(DPP_DEBUG_ERR, "error saving trusted bootstrapping key!\n");
            goto fin;
        }
    } else {
        dpp_debug(DPP_DEBUG_ANY, "FAILED TO AUTHENTICATE PEER!\n");
        EC_KEY_free(peer->peer_bootstrap);
        peer->peer_bootstrap = NULL;
    }

fin:
    if (ikm != NULL) {
        free(ikm);
    }
    if (keyx != NULL) {
        free(keyx);
    }
    if (S != NULL) {
        EC_POINT_free(S);
    }
    if (hctx != NULL) {
        HMAC_CTX_free(hctx);
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
process_pkex_exchange (pkex_frame *frame, int len, struct pkex_peer *peer)
{
    unsigned char machash[SHA512_DIGEST_LENGTH], *ptr, *status;
    unsigned int mdlen = 0;
    unsigned short grp;
    int ret = -1;
    BIGNUM *x = NULL, *y = NULL, *hmul = NULL, *order = NULL;
    EC_POINT *Q = NULL;
    TLV *tlv;
    EVP_MD_CTX *mdctx = NULL;

    if ((pkex_instance.bootstrap == NULL) || (pkex_instance.group == NULL) || (pkex_instance.group_num == 0)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to process PKEX frame, no bootstrap key!\n");
        goto fin;
    }
    if (peer->Y != NULL) {
        EC_POINT_free(peer->Y);
    }
    tlv = (TLV *)frame->attributes;
    if (!peer->initiator) {
        /*
         * if we're the responder then first get the group
         */
        if ((tlv = find_tlv(FINITE_CYCLIC_GROUP, frame->attributes, len)) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "malformed PKEX exchange, no group!\n");
            goto fin;
        }
        memcpy((unsigned short *)&grp, TLV_value(tlv), sizeof(unsigned short));
        grp = ieee_order(grp);
        if (grp != pkex_instance.group_num) {
            dpp_debug(DPP_DEBUG_ERR, "wrong group in exchange (found %d, expected %d)\n",
                      grp, pkex_instance.group_num);
            /* TODO: send a response with a better group */
            goto fin;
        }
        /*
         * next see if there's a code identifier
         */
        if ((tlv = find_tlv(CODE_IDENTIFIER, frame->attributes, len)) != NULL) {
            if (!pkex_instance.adds_identifier ||
                memcmp(pkex_instance.identifier, TLV_value(tlv),
                       strlen(pkex_instance.identifier))) {
                dpp_debug(DPP_DEBUG_ERR, "no matching code identifier\n");
                goto fin;
            }
        } else if (pkex_instance.adds_identifier) {
            dpp_debug(DPP_DEBUG_ERR, "missing code identifier\n");
            goto fin;
        }
        if ((tlv = find_tlv(ENCRYPTED_KEY, frame->attributes, len)) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "No encrypted key in PKEX exchange!\n");
            goto fin;
        }
    } else {
        /*
         * otherwise we're the initiator and there's a status
         */
        if ((tlv = find_tlv(DPP_STATUS, frame->attributes, len)) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "malformed PKEX exchange, no status!\n");
            goto fin;
        }
        status = TLV_value(tlv);
        switch (*status) {
            case STATUS_OK:
                break;
            case ERROR_BAD_GROUP:
                /* TODO: send a response saying it's a bad group */
                
                /* fall thru intentional */
            default:
                goto fin;
        }
        if ((tlv = find_tlv(ENCRYPTED_KEY, frame->attributes, len)) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "No encrypted key in PKEX exchange!\n");
            goto fin;
        }
    }
    
    if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
        ((mdctx = EVP_MD_CTX_new()) == NULL) || 
        ((peer->n = BN_new()) == NULL) ||
        ((peer->Y = EC_POINT_new(pkex_instance.group)) == NULL) ||
        ((Q = EC_POINT_new(pkex_instance.group)) == NULL) ||
        ((order = BN_new()) == NULL) || ((hmul = BN_new()) == NULL)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to create key for PKEX\n");
        goto fin;
    }
    if (!EC_GROUP_get_order(pkex_instance.group, order, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to obtain order from the group! Order! Order!!\n");
        goto fin;
    }
    /*
     * we now have an ENCRYPTED_KEY tlv....
     */
    ptr = TLV_value(tlv);
    /*
     * recover Y and the peer's nonce from the frame
     */
    BN_bin2bn(ptr, pkex_instance.primelen, x);
    ptr += pkex_instance.primelen;
    BN_bin2bn(ptr, pkex_instance.primelen, y);
    ptr += pkex_instance.primelen;

    pp_a_bignum(DPP_DEBUG_TRACE, peer->initiator ? "N.x" : "M.x", x);
    pp_a_bignum(DPP_DEBUG_TRACE, peer->initiator ? "N.y" : "M.y", y);
    
   /*
     * first make sure the encrypted point that was received is valid.
     */
    if (!EC_POINT_set_affine_coordinates_GFp(pkex_instance.group, peer->Y, x, y, bnctx) ||
        !EC_POINT_is_on_curve(pkex_instance.group, peer->Y, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "encrypted key is not on curve!\n");
        goto fin;
    }
    /*
     * the encrypted point is N so n = N.x which we need later for kdf context
     */
    BN_copy(peer->n, x);

    /*
     * next decrypt the point
     */
    EVP_DigestInit(mdctx, pkex_instance.hashfcn);
    EVP_DigestUpdate(mdctx, peer->peermac, ETH_ALEN);
    if (pkex_instance.adds_identifier) {
        print_buffer(DPP_DEBUG_TRACE, "adding identifier", (unsigned char *)pkex_instance.identifier,
                     strlen(pkex_instance.identifier));
        EVP_DigestUpdate(mdctx, pkex_instance.identifier, strlen(pkex_instance.identifier));
    }
    EVP_DigestUpdate(mdctx, pkex_instance.password, strlen(pkex_instance.password));
    EVP_DigestFinal(mdctx, machash, &mdlen);
    BN_bin2bn(machash, mdlen, hmul);
    BN_mod(hmul, hmul, order, bnctx);
    pp_a_bignum(DPP_DEBUG_TRACE, "H(peermac | [identifier | ] password)", hmul);
    pp_a_point(DPP_DEBUG_TRACE, 1, peer->initiator ? "Presp.x" : "Pinit.x", pkex_instance.Ppeer);

    if (!EC_POINT_mul(pkex_instance.group, Q, NULL, pkex_instance.Ppeer, hmul, bnctx) ||
        !EC_POINT_invert(pkex_instance.group, Q, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to create and invert Q' for PKEX!\n");
        goto fin;
    }
    if (!EC_POINT_add(pkex_instance.group, peer->Y, peer->Y, Q, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to encrypt pubkey for PKEX!\n");
        goto fin;
    }
    /*
     * check again, just to make sure
     */
    if (!EC_POINT_is_on_curve(pkex_instance.group, peer->Y, bnctx)) {
        dpp_debug(DPP_DEBUG_ERR, "decrypted key is not on the curve!\n");
        goto fin;
    }
    pp_a_point(DPP_DEBUG_TRACE, 1, peer->initiator ? "Y.x" : "X.x", peer->Y);

    ret = 1;
fin:
    if (x != NULL) {
        BN_free(x);
    }
    if (y != NULL) {
        BN_free(y);
    }
    if (hmul != NULL) {
        BN_free(hmul);
    }
    if (order != NULL) {
        BN_free(order);
    }
    if (mdctx != NULL) {
        EVP_MD_CTX_free(mdctx);
    }
    if (Q != NULL) {
        EC_POINT_free(Q);
    }
    return ret;
}

int 
process_pkex_frame (unsigned char *data, int len, unsigned char *mymac, unsigned char *peermac)
{
    pkex_frame *frame = (pkex_frame *)data;
    unsigned char broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    struct pkex_peer *peer = NULL;
    int keyidx;

    dpp_debug(DPP_DEBUG_STATE_MACHINE, "received %s from " MACSTR " to " MACSTR "\n", 
              frame_to_string(frame->frame_type), MAC2STR(peermac), MAC2STR(mymac));

    TAILQ_FOREACH(peer, &pkex_instance.peers, entry) {
        if ((memcmp(peer->mymac, mymac, ETH_ALEN) == 0) &&
            ((memcmp(peer->peermac, peermac, ETH_ALEN) == 0) ||
             (memcmp(peer->peermac, broadcast, ETH_ALEN) == 0))) {
            /*
             * if it's to us and from a known MAC it's a known entity, if it's
             * to us and to broadcast, let's record the sender and respond
             */
            memcpy(peer->peermac, peermac, ETH_ALEN);
            break;
        }
    }
    if (peer == NULL) {
        if (frame->frame_type != PKEX_SUB_EXCH_REQ) {
            dpp_debug(DPP_DEBUG_PROTOCOL_MSG, "gratuitous receipt of PKEX frame but not Exchange Request!\n");
            return -1;
        }
        /*
         * we are a gratuitous responder, this was picked up by us, so it 
         * is for us, it's a COMMIT, so let's respond!
         */
        if ((peer = (struct pkex_peer *)malloc(sizeof(struct pkex_peer))) == NULL) {
            dpp_debug(DPP_DEBUG_ERR, "unable to allocate peer to do PKEX!\n");
            return -1;
        }
        memcpy(peer->mymac, mymac, ETH_ALEN);
        memcpy(peer->peermac, peermac, ETH_ALEN);
        peer->state = PKEX_NOTHING;
        peer->X = NULL;
        peer->Y = NULL;
        peer->initiator = 0;
        peer->retrans = 0;
        TAILQ_INSERT_HEAD(&pkex_instance.peers, peer, entry);
    } else {
        /*
         * otherwise there's a retransmission timer set...
         */
        srv_rem_timeout(srvctx, peer->t0);
    }

    /*
     * fix up the lengths of the TLVs...
     */
    ieee_ize_attributes(frame->attributes, len - sizeof(pkex_frame));
    switch (peer->state) {
        case PKEX_NOTHING:
            if (peer->initiator) {
                dpp_debug(DPP_DEBUG_ERR, "initiator received a PKEX frame in NOTHING state\n");
                break;
            } else {
                if (frame->frame_type != PKEX_SUB_EXCH_REQ) {
                    dpp_debug(DPP_DEBUG_ERR, "responder did not receive PKEX exchange request in NOTHING\n");
                    break;
                }
                if (process_pkex_exchange(frame, len, peer) > 0) {
                    pkex_exchange_to_peer(peer, STATUS_OK);
                    compute_z(peer);
                    peer->t0 = srv_add_timeout(srvctx, SRV_SEC(2), retransmit_pkex, peer);
                }
            }
            break;
        case PKEX_SEND_EXCHANGE:
            if (peer->initiator) {
                if (frame->frame_type != PKEX_SUB_EXCH_RESP) {
                    dpp_debug(DPP_DEBUG_ERR, "initiator did not receive PKEX exchange response in SENT_EXCH\n");
                    peer->t0 = srv_add_timeout(srvctx, SRV_SEC(2), retransmit_pkex, peer);
                    break;
                }
                if (process_pkex_exchange(frame, len, peer) > 0) {
                    compute_z(peer);
                    pkex_reveal_to_peer(peer);
                    peer->t0 = srv_add_timeout(srvctx, SRV_SEC(2), retransmit_pkex, peer);
                }
            } else {
                if (frame->frame_type != PKEX_SUB_COM_REV_REQ) {
                    dpp_debug(DPP_DEBUG_ERR, "responder did not receive PKEX reveal request in SENT_EXCH\n");
                    peer->t0 = srv_add_timeout(srvctx, SRV_SEC(2), retransmit_pkex, peer);
                    break;
                }
                if ((keyidx = process_pkex_reveal(frame, len, peer)) < 1) {
                    dpp_debug(DPP_DEBUG_ERR, "PKEX: responder cannot process reveal request!\n");
                    return -1;
                }
                pkex_reveal_to_peer(peer);
                /*
                 * kick off DPP!
                 */
                bootstrap_peer(peer->mymac, keyidx, peer->initiator, 1);
                peer->state = PKEX_FINISHED;
            }
            break;
        case PKEX_SEND_COMREV:
            if (!peer->initiator) {
                dpp_debug(DPP_DEBUG_ERR, "responder already finished!\n");
                break;
            }
            if (frame->frame_type != PKEX_SUB_COM_REV_RESP) {
                dpp_debug(DPP_DEBUG_ERR, "PKEX: intiator did not receive PKEX Commit/Reveal Response!\n");
                peer->t0 = srv_add_timeout(srvctx, SRV_SEC(2), retransmit_pkex, peer);
                break;
            }
            if ((keyidx = process_pkex_reveal(frame, len, peer)) < 1) {
                dpp_debug(DPP_DEBUG_ERR, "PKEX: initiator cannot process reveal response!\n");
                return -1;
            }
            /*
             * kick off DPP!
             */
            bootstrap_peer(peer->mymac, keyidx, peer->initiator, 1);
            peer->state = PKEX_FINISHED;
            break;
        case PKEX_FINISHED:
        default:
            /*
             * try and sync back up
             */
            pkex_reveal_to_peer(peer);
            dpp_debug(DPP_DEBUG_ERR, "PKEX: already done! Sending reveal again\n");
            break;
    }
    return 1;
}

int
pkex_initiate(unsigned char *mymac, unsigned char *targetmac)
{
    struct pkex_peer *peer;
    int ret;

    if ((peer = (struct pkex_peer *)malloc(sizeof(struct pkex_peer))) == NULL) {
        return -1;
    }
    memcpy(peer->mymac, mymac, ETH_ALEN);
    memcpy(peer->peermac, targetmac, ETH_ALEN);
    peer->X = NULL;
    peer->Y = NULL;
    peer->state = PKEX_NOTHING;
    peer->initiator = 1;
    peer->retrans = 0;
    TAILQ_INSERT_HEAD(&pkex_instance.peers, peer, entry);
    ret = pkex_exchange_to_peer(peer, STATUS_OK);
    peer->t0 = srv_add_timeout(srvctx, SRV_SEC(2), retransmit_pkex, peer);
    return ret;
}

int
pkex_initialize (int whatkind, char *password, char *id, char *info, char *keyfile, char *bsfile,
                 int opclass, int channel, int verbosity)
{
    FILE *fp;
    BIO *bio = NULL;
    int ret = 0;
    BIGNUM *prime = NULL;
    const BIGNUM *priv = NULL;
    const EC_POINT *Pub = NULL;

    /*
     * initialize globals 
     */
    if ((bnctx = BN_CTX_new()) == NULL) {
        fprintf(stderr, "cannot create bignum context!\n");
        return -1;
    }
    init_or_resp = whatkind;
    pkex_instance.group_num = 0;
    pkex_instance.opclass = opclass;
    pkex_instance.channel = channel;
    debug = verbosity;
    strcpy(pkex_instance.bsfile, bsfile);
    strcpy(pkex_instance.password, password);
    if (id != NULL) {
        strcpy(pkex_instance.identifier, id);
        pkex_instance.adds_identifier = 1;
    } else {
        pkex_instance.adds_identifier = 0;
    }
    /*
     * read in our bootstrapping key
     */
    if ((fp = fopen(keyfile, "r")) == NULL) {
        fprintf(stderr, "PKEX: unable to open keyfile %s\n", keyfile);
        return -1;
    }
    bio = BIO_new(BIO_s_file());
    BIO_set_fp(bio, fp, BIO_CLOSE);
    if ((pkex_instance.bootstrap = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL)) == NULL) {
        fprintf(stderr, "PKEX: unable to read key in keyfile %s\n", keyfile);
        ret = -1;
        goto fin;
    }
    BIO_free(bio);

    /*
     * figure out what group our bootstrap key is in and how big that 
     * prime is (handy when constructing and parsing messages)
     */
    if (((pkex_instance.group = EC_KEY_get0_group(pkex_instance.bootstrap)) == NULL) ||
        ((prime = BN_new()) == NULL) ||
        !EC_GROUP_get_curve_GFp(pkex_instance.group, prime, NULL, NULL, bnctx)) {
        fprintf(stderr, "DDP: unable to get group of bootstrap key\n");
        ret = -1;
        goto fin;
    }
    pkex_instance.primelen = BN_num_bytes(prime);
    pkex_instance.nid = EC_GROUP_get_curve_name(pkex_instance.group);
    switch (pkex_instance.nid) {
        case NID_X9_62_prime256v1:
            pkex_instance.group_num = 19;
            pkex_instance.hashfcn = EVP_sha256();
            pkex_instance.digestlen = 32;
            break;
        case NID_secp384r1:
            pkex_instance.group_num = 20;
            pkex_instance.hashfcn = EVP_sha384();
            pkex_instance.digestlen = 48;
            break;
        case NID_secp521r1:
            pkex_instance.group_num = 21;
            pkex_instance.hashfcn = EVP_sha512();
            pkex_instance.digestlen = 64;
            break;
#ifdef HAS_BRAINPOOL
        case NID_brainpoolP256r1:
            pkex_instance.group_num = 28;
            pkex_instance.hashfcn = EVP_sha256();
            pkex_instance.digestlen = 32;
            break;
        case NID_brainpoolP384r1:
            pkex_instance.group_num = 29;
            pkex_instance.hashfcn = EVP_sha384();
            pkex_instance.digestlen = 48;
            break;
        case NID_brainpoolP512r1:
            pkex_instance.group_num = 30;
            pkex_instance.hashfcn = EVP_sha512();
            pkex_instance.digestlen = 64;
            break;
#endif  /* HAS_BRAINPOOL */
        default:
            dpp_debug(DPP_DEBUG_ERR, "bootstrap key from unknown group!\n");
            ret = -1;
            goto fin;
    }
    EVP_add_digest(pkex_instance.hashfcn);
    if (pkex_instance.hashfcn != EVP_sha256()) {
        EVP_add_digest(EVP_sha256());   /* to hash bootstrapping keys */
    }
    if (!find_fixed_elements(init_or_resp)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to set fixed elements\n");
        ret = -1;
        goto fin;
    }
    TAILQ_INIT(&pkex_instance.peers);

    if (((priv = EC_KEY_get0_private_key(pkex_instance.bootstrap)) == NULL) ||
        ((Pub = EC_KEY_get0_public_key(pkex_instance.bootstrap)) == NULL)) {
        dpp_debug(DPP_DEBUG_ERR, "unable to obtain public/private bootstrap keypair\n");
        goto fin;
    }
    pp_a_bignum(DPP_DEBUG_TRACE, "bootstrapping private key", (BIGNUM *)priv);
    pp_a_point(DPP_DEBUG_TRACE, 0, "bootstrapping public key", (EC_POINT *)Pub);

    ret = 1;
fin:
    if (prime != NULL) {
        BN_free(prime);
    }
    return ret;
}


