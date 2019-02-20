/*
 * Copyright (c) Dan Harkins, 2008, 2009, 2010, 2016
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
 *     3. All advertising materials and documentation mentioning features
 *	  or use of this software must display the following acknowledgement:
 *
 *        "This product includes software written by
 *         Dan Harkins (dharkins at lounge dot org)"
 *
 *  "DISCLAIMER OF LIABILITY
 *  
 *  THIS SOFTWARE IS PROVIDED BY DAN HARKINS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
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
 * this code cannot simply be copied and put under a different distribution
 * license (including the GNU public license).
 */

#ifndef _FRAME_H_
#define _FRAME_H_

#if __BYTE_ORDER == __LITTLE_ENDIAN
/*
 * IEEE does things bassackwards, networking in non-network order.
 */
#define ieee_order(x)   (x)                     /* if LE, do nothing */
#else

static inline unsigned short
ieee_order (unsigned short x)                   /* if BE, byte-swap */
{
    return ((x & 0xff) << 8) | (x >> 8);
}

#endif  /* __LITTLE_ENDIAN */

/*
 * some useful defines...
 */

#ifndef MAC2STR
#define MAC2STR(a) (a)[0]&0xff, (a)[1]&0xff, (a)[2]&0xff, (a)[3]&0xff, (a)[4]&0xff, (a)[5]&0xff
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

#define IEEE802_11_FC_GET_TYPE(fc)  (((fc) & 0x000c) >> 2)
#define IEEE802_11_FC_GET_STYPE(fc) (((fc) & 0x00f0) >> 4)

#define WLAN_STATUS_SUCCESSFUL                  0
#define WLAN_STATUS_UNSPECIFIED_FAILURE         1
#define WLAN_STATUS_AUTHENTICATION_TIMEOUT      16
#define WLAN_STATUS_REQUEST_DECLINED            37
#define WLAN_STATUS_ANTI_CLOGGING_TOKEN_NEEDED  76
#define WLAN_STATUS_NOT_SUPPORTED_GROUP         77

#define IEEE802_11_IE_SSID                      0
#define IEEE802_11_HDR_LEN                      24

#define ETH_ALEN                                6

#define PMK_LEN                                 64  /* could be product of SHA512 */
#define PMKID_LEN                               16

/*
 * some prefix matches for the NL80211 interface under linux
 */
#define DPP_PUB_ACTION_MATCH "\x04\x09\x50\x6f\x9a\x1a"
#define DPP_PUB_ACTION_MATCH_LEN 6
#define GAS_INITIAL_REQ_MATCH "\x04\x0a"
#define GAS_INITIAL_REQ_MATCH_LEN 2
#define GAS_INITIAL_RESP_MATCH "\x04\x0b"
#define GAS_INITIAL_RESP_MATCH_LEN 2
#define GAS_COMEBACK_REQ_MATCH "\x04\x0c"
#define GAS_COMEBACK_REQ_MATCH_LEN 2
#define GAS_COMEBACK_RESP_MATCH "\x04\x0d"
#define GAS_COMEBACK_RESP_MATCH_LEN 2

/*
 * all we're interested in is mgmt frames of subtype beacon, auth, and
 * action so instead of depending on platform-specific data structures 
 * just declare our own minimal one.
 */
struct ieee80211_mgmt_frame {
    unsigned short frame_control;
#define IEEE802_11_FC_TYPE_MGMT 0
#define IEEE802_11_FC_STYPE_BEACON 8
#define IEEE802_11_FC_STYPE_AUTH 11
#define IEEE802_11_FC_STYPE_ACTION 13
    unsigned short duration;
    unsigned char da[ETH_ALEN];
    unsigned char sa[ETH_ALEN];
    unsigned char bssid[ETH_ALEN];
    unsigned short seq;
    union {
        struct {
#define SAE_AUTH_ALG                    3
            unsigned short alg;
#define SAE_AUTH_COMMIT                 1
#define SAE_AUTH_CONFIRM                2
            unsigned short auth_seq;
            unsigned short status;
            unsigned char variable[0];
        } __attribute__ ((packed)) authenticate;
        struct {
            unsigned char timestamp[8];
            unsigned short interval;
            unsigned short capabilities;
            unsigned char variable[0];
        } __attribute__ ((packed)) beacon;
        struct {
            unsigned char category;
#define ACTION_PUBLIC                   4
#define ACTION_MESH                     13
#define ACTION_SELF_PROTECTED           15
#define ACTION_PRIVATE_PROTECTED        126
#define ACTION_PRIVATE                  127
            unsigned char field;
#define PUB_ACTION_VENDOR               9
#define GAS_INITIAL_REQUEST             10
#define GAS_INITIAL_RESPONSE            11
#define GAS_COMEBACK_REQUEST            12
#define GAS_COMEBACK_RESPONSE           13
            unsigned char variable[0];
        } __attribute__ ((packed)) action;
    };
} __attribute__ ((packed));

/*
 * for PKEX and DPP auth frames
 */
typedef struct _dpp_action_frame {
    unsigned char oui_type[4];
    unsigned char cipher_suite;
    unsigned char frame_type;
#define DPP_SUB_AUTH_REQUEST        0
#define DPP_SUB_AUTH_RESPONSE       1
#define DPP_SUB_AUTH_CONFIRM        2
#define DPP_SUB_PEER_DISCOVER_REQ   5
#define DPP_SUB_PEER_DISCOVER_RESP  6
#define PKEX_SUB_EXCH_REQ           7
#define PKEX_SUB_EXCH_RESP          8
#define PKEX_SUB_COM_REV_REQ        9
#define PKEX_SUB_COM_REV_RESP       10
    unsigned char attributes[0];
} __attribute__ ((packed)) dpp_action_frame;

/*
 * for DPP Config frames
 */
typedef struct _gas_action_req_frame {
    unsigned char dialog_token;
    unsigned char ad_proto_elem[3];
    unsigned char ad_proto_id[7];
    unsigned short query_reqlen;
    unsigned char query_req[0];
} __attribute__ ((packed)) gas_action_req_frame;

typedef struct _gas_action_comeback_req_frame {
    unsigned char dialog_token;
} __attribute__ ((packed)) gas_action_comeback_req_frame;

typedef struct _gas_action_resp_frame {
    unsigned char dialog_token;
    unsigned short status_code;
    unsigned short comeback_delay;
    unsigned char ad_proto_elem[3];
    unsigned char ad_proto_id[7];
    unsigned short query_resplen;
    unsigned char query_resp[0];
} __attribute__ ((packed)) gas_action_resp_frame;

typedef struct _gas_action_comeback_resp_frame {
    unsigned char dialog_token;
    unsigned short status_code;
    unsigned char fragment_id;
    unsigned short comeback_delay;
    unsigned char ad_proto_elem[3];
    unsigned char ad_proto_id[7];
    unsigned short query_resplen;
    unsigned char query_resp[0];
} __attribute__ ((packed)) gas_action_comeback_resp_frame;

#endif  /* _FRAME_H_ */
