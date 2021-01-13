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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>              /* DELETE ME WITH SCAN STUFF */
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/bpf.h>
#include <net/route.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_freebsd.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include "ieee802_11.h"
#include "service.h"
#include "radio.h"
#include "common.h"
#include "tlv.h"
#include "pkex.h"
#include "dpp.h"

struct interface {
    TAILQ_ENTRY(interface) entry;
    char ifname[IFNAMSIZ];
    unsigned char bssid[ETH_ALEN];
    unsigned char bkhash[SHA256_DIGEST_LENGTH];
    unsigned char is_loopback;
    int fd;     /* BPF socket */
};
TAILQ_HEAD(bar, interface) interfaces;

#define WIRELESS_MTU    1300

struct cstate {
    TAILQ_ENTRY(cstate) entry;
    unsigned char peeraddr[ETH_ALEN];
    unsigned char myaddr[ETH_ALEN];
    unsigned char bkhash[SHA256_DIGEST_LENGTH];
    gas_action_comeback_resp_frame cbresp_hdr;
    char *buf;
    int left;
    int sofar;
    timerid t;
    int fd;
};
TAILQ_HEAD(foo, cstate) cstates;

service_context srvctx;
unsigned int opclass, channel;
char bootstrapfile[80], controller[30];
unsigned short portin, portout;

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

/*
 * cons up an action frame and send it out the interface
 */
static int 
cons_action_frame (unsigned char field, 
                   unsigned char *mymac, unsigned char *peermac, 
                   char *data, int len)
{
    char buf[2048];
    struct interface *inf = NULL;
    struct ieee80211_mgmt_frame *frame;
    unsigned char broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    unsigned long af;
    size_t framesize;

    memset(buf, 0, 2048);
    TAILQ_FOREACH(inf, &interfaces, entry) {
        if (memcmp(mymac, inf->bssid, ETH_ALEN) == 0) {
            break;
        }
    }
    if (inf == NULL) {
        fprintf(stderr, "can't find interface to send mgmt frame!\n");
        return -1;
    }
    framesize = IEEE802_11_HDR_LEN + sizeof(frame->action) + len;
    memset(buf, 0, sizeof(buf));
    if (inf->is_loopback) {
        /*
         * add the loopback pseudo-header to indicate the AF
         */
        af = AF_INET;
        memcpy(buf, &af, sizeof(unsigned long));
        framesize += sizeof(unsigned long);
        frame = (struct ieee80211_mgmt_frame *)(buf + sizeof(unsigned long));
    } else {
        frame = (struct ieee80211_mgmt_frame *)buf;
    }
    printf("sending %d byte action frame from " MACSTR " to " MACSTR "\n", len, 
           MAC2STR(mymac), MAC2STR(peermac));
    /*
     * fill in the action frame header
     */
    frame->frame_control = ieee_order((IEEE802_11_FC_TYPE_MGMT << 2 | IEEE802_11_FC_STYPE_ACTION << 4));
    memcpy(frame->sa, mymac, ETH_ALEN);
    memcpy(frame->da, peermac, ETH_ALEN);
    memcpy(frame->bssid, broadcast, ETH_ALEN);
    frame->action.category = ACTION_PUBLIC;
    frame->action.field = field;
    memcpy(frame->action.variable, data, len);
    if (write(inf->fd, buf, framesize) < 0) {
        fprintf(stderr, "unable to write management frame!\n");
        return -1;
    }
    return len;
}

static int
cons_next_fragment (struct cstate *cs)
{
    char buffer[WIRELESS_MTU+sizeof(gas_action_comeback_resp_frame)];
    gas_action_comeback_resp_frame *cb_resp;
    
    if (cs->buf == NULL) {
        fprintf(stderr, "trying to send next fragment of NULL!\n");
        return 0;
    }
    /*
     * technically it's MTU+sizeof(comeback response header)....
     * just don't set WIRELESS_MTU to be *exactly* the MTU
     *
     * Copy over the comeback response header
     */
    cb_resp = (gas_action_comeback_resp_frame *)&buffer[0];
    memcpy(cb_resp, &cs->cbresp_hdr, sizeof(gas_action_comeback_resp_frame));
    cb_resp->comeback_delay = 0;
    cb_resp->fragment_id = cs->left/WIRELESS_MTU;
    if (cs->left > WIRELESS_MTU) {
        printf("sending next fragment of %d to " MACSTR ", %d so far and %d left\n",
               WIRELESS_MTU, MAC2STR(cs->peeraddr), cs->sofar, cs->left);
        cb_resp->query_resplen = WIRELESS_MTU;
        cb_resp->fragment_id |= 0x80;  // more fragme
        memcpy(cb_resp->query_resp, cs->buf+cs->sofar, WIRELESS_MTU);
        cons_action_frame(GAS_COMEBACK_RESPONSE, cs->myaddr, cs->peeraddr,
                          buffer, WIRELESS_MTU + sizeof(gas_action_comeback_resp_frame));
        cs->sofar += WIRELESS_MTU;
        cs->left -= WIRELESS_MTU;
    } else {
        cb_resp->query_resplen = cs->left;
        printf("sending final fragment of %d to " MACSTR ", %d so far and %d left\n",
               cs->left, MAC2STR(cs->peeraddr), cs->sofar, cs->left);
        memcpy(cb_resp->query_resp, cs->buf+cs->sofar, cs->left);
        cons_action_frame(GAS_COMEBACK_RESPONSE, cs->myaddr, cs->peeraddr,
                          buffer, cs->left + sizeof(gas_action_comeback_resp_frame));
        cs->sofar = cs->left = 0;
        memset(&cs->cbresp_hdr, 0, sizeof(gas_action_comeback_resp_frame));
        free(cs->buf); cs->buf = NULL;
    }
    return cs->left;
}

void
message_from_controller (int fd, void *data)
{
    struct cstate *cs = (struct cstate *)data;
    gas_action_comeback_resp_frame *cb_resp;
    char buf[3000];
    uint32_t netlen;
    int len, rlen, ret;

    if ((ret = read(cs->fd, (char *)&netlen, sizeof(uint32_t))) < 0) {
        fprintf(stderr, "unable to read message from controller (%d)!\n", ret);
        perror("read");
        srv_rem_input(srvctx, cs->fd);
        close(cs->fd);
        return;
    }
    netlen = ntohl(netlen);
    if (netlen > sizeof(buf)) {
        fprintf(stderr, "overflow attack by controller! Not gonna read in %d bytes\n",
                netlen);
        srv_rem_input(srvctx, cs->fd);
        close(cs->fd);
        return;
    }
    len = 0;
    while(netlen) {
        if ((rlen = read(cs->fd, (buf + len), netlen)) < 1) {
            fprintf(stderr, "unable to read message from controller!\n");
            srv_rem_input(srvctx, cs->fd);
            close(cs->fd);
            return;
        }
        len += rlen;
        netlen -= rlen;
    }
    if (len == 0) {
        srv_rem_input(srvctx, cs->fd);
        close(cs->fd);
        return;
    }
        
    printf("read %d byte message from controller\n", len);

    if (cs->left) {
        fprintf(stderr, "we're still defraging the last message, chill!\n");
        return;
    }
    if (len > WIRELESS_MTU) {
        if (buf[0] != GAS_COMEBACK_RESPONSE) {
            fprintf(stderr, "dropping message larger than %d that cannot be fragmented!\n",
                    WIRELESS_MTU);
            return;
        }
        len--;
        /*
         * keep a copy of the comeback response header for each fragment
         */
        cb_resp = (gas_action_comeback_resp_frame *)&buf[1];
        memcpy(&cs->cbresp_hdr, cb_resp, sizeof(gas_action_comeback_resp_frame));
        len -= sizeof(gas_action_comeback_resp_frame);

        if ((cs->buf = malloc(len)) == NULL) {
            fprintf(stderr, "unable to allocate space to fragment %d byte message!\n", len);
            return;
        }
        /*
         * the actual response is copied into the buffer that gets fragmented
         */
        printf("need to fragment message that is %d, buffer is %d\n",
               cb_resp->query_resplen, len);
        memcpy(cs->buf, cb_resp->query_resp, len);
        print_buffer("First 32 octets that I'm gonna fragment", cs->buf, 32); 
        cs->sofar = 0;
        cs->left = len;
        cons_next_fragment(cs);
    } else {
        printf("sending message from " MACSTR " to " MACSTR "\n\n",
               MAC2STR(cs->myaddr), MAC2STR(cs->peeraddr));
        if (cons_action_frame(buf[0], cs->myaddr, cs->peeraddr,
                              &buf[1], len - 1) < 1) {
            fprintf(stderr, "unable to send message from controller to peer!\n");
            srv_rem_input(srvctx, cs->fd);
            close(cs->fd);
            return;
        }
    }
    return;
}

void
delete_cstate (timerid t, void *data)
{
    struct cstate *cs = (struct cstate *)data;

    printf("deleting connection state....\n");
    TAILQ_REMOVE(&cstates, cs, entry);
    srv_rem_input(srvctx, cs->fd);
    if (cs->left) {
        free(cs->buf);
    }
    close(cs->fd);
    free(cs);

    return;
}

/*
 * bpf_in()
 *      handle input on a BPF socket
 */
static void
bpf_in (int fd, void *data)
{
    struct interface *inf = (struct interface *)data;
    struct ieee80211_mgmt_frame *frame;
    dpp_action_frame *dpp;
    struct cstate *cs;
    TLV *tlv;
    unsigned short frame_control;
    int type, stype, left, len, framesize;
    unsigned char broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    struct bpf_hdr *hdr;
    struct sockaddr_in clnt;
    char buf[2048], tocontroller[2048], *ptr;
    uint32_t tcpbuflen;

    if ((len = read(fd, buf, sizeof(buf))) < 0) {
        fprintf(stderr, "can't read off bpf socket!\n");
        perror("read");
        return;
    }

    ptr = buf;
    while (len > 0) {
        hdr = (struct bpf_hdr *)ptr;
        /*
         * if loopback skip over the BPF's pseudo header.
         */
        if (inf->is_loopback) {
            frame = (struct ieee80211_mgmt_frame *)(ptr + hdr->bh_hdrlen + sizeof(unsigned long));
            framesize = hdr->bh_datalen - sizeof(unsigned long);
        } else {
            frame = (struct ieee80211_mgmt_frame *)(ptr + hdr->bh_hdrlen);
            framesize = hdr->bh_datalen;
        }
        if (framesize > len) {
            fprintf(stderr, "something is seriously fucked up! read %d, frame is %d\n",
                    len, framesize);
            return;
        }
        /*
         * if we sent it, ignore it
         */
        if (memcmp(frame->sa, inf->bssid, ETH_ALEN) == 0) {
            fprintf(stderr, "it's ours, ignore\n");
            len -= BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
            ptr += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
            continue;
        }
        /*
         * if it's not for us and not broadcast, ignore it
         */
        if (memcmp(frame->da, inf->bssid, ETH_ALEN) &&
            memcmp(frame->da, broadcast, ETH_ALEN)) {
            fprintf(stderr, "it's not for us, da is " MACSTR ", ignore\n", MAC2STR(frame->da));
            len -= BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
            ptr += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
            continue;
        }
        frame_control = ieee_order(frame->frame_control);
        type = IEEE802_11_FC_GET_TYPE(frame_control);
        stype = IEEE802_11_FC_GET_STYPE(frame_control);

        memset(tocontroller, 0, 2048);
        /*
         * if it's not a public action frame then we don't care about it!
         */
        if (type == IEEE802_11_FC_TYPE_MGMT) {
            switch (stype) {
                case IEEE802_11_FC_STYPE_ACTION:
                    if (frame->action.category != ACTION_PUBLIC) {
                        continue;
                    }
                    left = framesize - (IEEE802_11_HDR_LEN + sizeof(frame->action));
                    printf("got an action frame from " MACSTR "!\n", MAC2STR(frame->sa));
                    switch (frame->action.field) {
                        case PUB_ACTION_VENDOR:
                            /* 
                             * PKEX, DPP Auth, and DPP Discovery
                             */
                            dpp = (dpp_action_frame *)frame->action.variable;
                            switch (dpp->frame_type) {
                                /*
                                 * DPP Auth
                                 */
                                case DPP_SUB_AUTH_REQUEST:
                                    tlv = (TLV *)dpp->attributes;  // Br -- check whether for controller
                                    if ((TLV_length(tlv) != SHA256_DIGEST_LENGTH) ||
                                        (TLV_type(tlv) != RESPONDER_BOOT_HASH) ||
                                        memcmp(inf->bkhash, TLV_value(tlv), SHA256_DIGEST_LENGTH)) {
                                        break;
                                    }
                                    /* fall through intentional */
                                case DPP_CHIRP:
                                case PKEX_SUB_EXCH_REQ:
                                    printf("received %s\n", dpp->frame_type == DPP_CHIRP ? "chirp" : \
                                           dpp->frame_type == DPP_SUB_AUTH_REQUEST ? "DPP Auth Request" : \
                                           "PKEX Exchange Request");
                                    /*
                                     * a gratuitous request, create new client state...
                                     */
                                    if ((cs = (struct cstate *)malloc(sizeof(struct cstate))) == NULL) {
                                        return;
                                    }
                                    memset(cs, 0, sizeof(struct cstate));
                        
                                    memset((char *)&clnt, 0, sizeof(struct sockaddr_in));

                                    /*
                                     * connect to the controller
                                     */
                                    clnt.sin_family = AF_INET;
                                    clnt.sin_addr.s_addr = inet_addr(controller);
                                    clnt.sin_port = htons(portout);
                                    if ((cs->fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                                        fprintf(stderr, "Can't create socket to send frame to controller!\n");
                                        free(cs);
                                        return;
                                    }
                                    if (connect(cs->fd, (struct sockaddr *)&clnt, sizeof(struct sockaddr_in)) < 0) {
                                        fprintf(stderr, "Can't send frame to controller!\n");
                                        close(cs->fd);
                                        free(cs);
                                        return;
                                    }
                                    memcpy(cs->peeraddr, frame->sa, ETH_ALEN);
                                    memcpy(cs->myaddr, inf->bssid, ETH_ALEN);
                                    if (dpp->frame_type == DPP_SUB_AUTH_REQUEST) {
                                        tlv = (TLV *)dpp->attributes;
                                        tlv = TLV_next(tlv);    // point to Br after Status
                                        memcpy(cs->bkhash, tlv->value, SHA256_DIGEST_LENGTH);
                                    }
                                    /*
                                     * add the new client state to the list and set the socket callback
                                     */
                                    TAILQ_INSERT_TAIL(&cstates, cs, entry);
                                    srv_add_input(srvctx, cs->fd, cs, message_from_controller);
                                    cs->t = srv_add_timeout(srvctx, SRV_SEC(10), delete_cstate, cs);

                                    tcpbuflen = htonl(left+1);
                                    memcpy(tocontroller, (unsigned char *)&tcpbuflen, sizeof(uint32_t));
                                    memcpy(tocontroller + sizeof(uint32_t),
                                           (unsigned char *)&frame->action.field, left+1);
                                    /*
                                     * send the message to the controller
                                     */
                                    printf("sending %d byte message from " MACSTR " back to controller...\n\n",
                                           left+1, MAC2STR(cs->peeraddr));
                                    print_buffer("message", tocontroller, left+1+sizeof(uint32_t));
                                    if (write(cs->fd, (unsigned char *)tocontroller, left+1+sizeof(uint32_t)) < 1) {
                                        fprintf(stderr, "relay: unable to send length of message to controller!\n");
                                    }
                                    printf("sent message to controller\n");
                                    break;
                                case DPP_SUB_AUTH_RESPONSE:
                                    printf("received auth response\n");
                                    tlv = (TLV *)frame->action.variable;
                                    tlv = TLV_next(tlv);    // point to Br after Status
                                    /*
                                     * find the outstanding client state structure
                                     */
                                    TAILQ_FOREACH(cs, &cstates, entry) {
                                        printf("checking whether " MACSTR " equals " MACSTR "\n",
                                               MAC2STR(cs->peeraddr), MAC2STR(frame->sa));
                                        if (memcmp(cs->peeraddr, frame->sa, ETH_ALEN) == 0) {
                                            break;
                                        }
                                        if ((memcmp(cs->peeraddr, broadcast, ETH_ALEN) == 0) &&
                                            (memcmp(cs->bkhash, tlv->value, SHA256_DIGEST_LENGTH) == 0)) {
                                            memcpy(cs->peeraddr, frame->sa, ETH_ALEN);
                                            break;
                                        }
                                    }
                                    if (cs == NULL) {
                                        printf("didn't find state for peer at " MACSTR "\n",
                                               MAC2STR(frame->sa));
                                        return;
                                    }
                                    srv_rem_timeout(srvctx, cs->t);
                                    memcpy(cs->myaddr, frame->da, ETH_ALEN);

                                    tcpbuflen = htonl(left+1);
                                    memcpy(tocontroller, (unsigned char *)&tcpbuflen, sizeof(uint32_t));
                                    memcpy(tocontroller + sizeof(uint32_t),
                                           (unsigned char *)&frame->action.field, left+1);
                                    printf("sending %d byte message from " MACSTR " back to controller...\n\n",
                                           left+sizeof(uint32_t), MAC2STR(cs->peeraddr));
                                    print_buffer("message", tocontroller, left+1+sizeof(uint32_t));
                                    if (write(cs->fd, (unsigned char *)tocontroller, left+1+sizeof(uint32_t)) < 1) {
                                        fprintf(stderr, "relay: unable to send length of message to controller!\n");
                                    }
                                    printf("sent message to controller!\n");
                                    cs->t = srv_add_timeout(srvctx, SRV_SEC(10), delete_cstate, cs);
                                    break;
                                case DPP_SUB_AUTH_CONFIRM:
                                case DPP_SUB_PEER_DISCOVER_REQ:
                                case DPP_SUB_PEER_DISCOVER_RESP:
                                case PKEX_SUB_COM_REV_REQ:
                                case PKEX_SUB_COM_REV_RESP:
                                case DPP_CONFIG_RESULT:
                                    printf("received %s\n", dpp->frame_type == DPP_SUB_AUTH_CONFIRM ? "Auth Confirm" : \
                                           dpp->frame_type == DPP_SUB_PEER_DISCOVER_REQ ? "DPP Peer Discovery Request" : \
                                           dpp->frame_type == DPP_SUB_PEER_DISCOVER_RESP ? "DPP Peer Discovery Response" : \
                                           dpp->frame_type == DPP_CONFIG_RESULT ? "DPP Config Result" : \
                                           "some PKEX frame\n");
                                    /*
                                     * find the client state and send this off!
                                     */
                                    TAILQ_FOREACH(cs, &cstates, entry) {
                                        if (memcmp(cs->peeraddr, frame->sa, ETH_ALEN) == 0) {
                                            break;
                                        }
                                    }
                                    if (cs == NULL) {
                                        return;
                                    }
                                    srv_rem_timeout(srvctx, cs->t);
                                    tcpbuflen = htonl(left+1);
                                    memcpy(tocontroller, (unsigned char *)&tcpbuflen, sizeof(uint32_t));
                                    memcpy(tocontroller + sizeof(uint32_t),
                                           (unsigned char *)&frame->action.field, left+1);

                                    printf("sending %d byte message from " MACSTR " back to controller...\n\n",
                                           left+1, MAC2STR(cs->peeraddr));
                                    print_buffer("message", tocontroller, left+1+sizeof(uint32_t));
                                    if (write(cs->fd, (unsigned char *)tocontroller, left+1+sizeof(uint32_t)) < 1) {
                                        fprintf(stderr, "relay: unable to send length of message to controller!\n");
                                    }
                                    printf("sent message to controller!\n");
                                    cs->t = srv_add_timeout(srvctx, SRV_SEC(10), delete_cstate, cs);
                                    break;
                                case PKEX_SUB_EXCH_RESP:
                                    printf("PKEX exchange response\n");
                                    tlv = (TLV *)frame->action.variable;
                                    tlv = TLV_next(tlv);    // point to Identifier after group
                                    /*
                                     * find the outstanding client state structure
                                     */
                                    TAILQ_FOREACH(cs, &cstates, entry) {
                                        if ((memcmp(cs->peeraddr, broadcast, ETH_ALEN) == 0) &&
                                            (memcmp(cs->bkhash, tlv->value,
                                                    TLV_length(tlv) < SHA256_DIGEST_LENGTH ?
                                                    TLV_length(tlv) : SHA256_DIGEST_LENGTH) == 0)) {
                                            memcpy(cs->peeraddr, frame->sa, ETH_ALEN);
                                            break;
                                        }
                                        if (memcmp(cs->peeraddr, frame->sa, ETH_ALEN) == 0) {
                                            break;
                                        }
                                    }
                                    if (cs == NULL) {
                                        return;
                                    }
                                    srv_rem_timeout(srvctx, cs->t);
                                    memcpy(cs->myaddr, frame->da, ETH_ALEN);

                                    tcpbuflen = htonl(left+1);
                                    memcpy(tocontroller, (unsigned char *)&tcpbuflen, sizeof(uint32_t));
                                    memcpy(tocontroller + sizeof(uint32_t),
                                           (unsigned char *)&frame->action.field, left+1);

                                    printf("sending %d byte message from " MACSTR " back to controller...\n\n",
                                           left+sizeof(uint32_t), MAC2STR(cs->peeraddr));
                                    print_buffer("message", tocontroller, left+1+sizeof(uint32_t));
                                    if (write(cs->fd, (unsigned char *)tocontroller, left+1+sizeof(uint32_t)) < 1) {
                                        fprintf(stderr, "relay: unable to send length of message to controller!\n");
                                    }
                                    cs->t = srv_add_timeout(srvctx, SRV_SEC(10), delete_cstate, cs);
                                    break;
                                default:
                                    fprintf(stderr, "unknown DPP frame %d\n", dpp->frame_type);
                                    break;
                            }
                            break;
                            /*
                             * DPP Configuration protocol
                             */
                        case GAS_INITIAL_REQUEST:
                        case GAS_INITIAL_RESPONSE:
                        case GAS_COMEBACK_REQUEST:
                        case GAS_COMEBACK_RESPONSE:
                            printf("received %s\n", frame->action.field == GAS_INITIAL_REQUEST ? "GAS Initial Request" : \
                                   frame->action.field == GAS_INITIAL_RESPONSE ? "GAS Initial Response" : \
                                   frame->action.field == GAS_COMEBACK_REQUEST ? "GAS Comeback Request" : \
                                   frame->action.field == GAS_COMEBACK_RESPONSE ? "GAS Comeback Response" : \
                                   "some unknown frame\n");
                            /*
                             * find the client state and send this off!
                             */
                            TAILQ_FOREACH(cs, &cstates, entry) {
                                if (memcmp(cs->peeraddr, frame->sa, ETH_ALEN) == 0) {
                                    break;
                                }
                            }
                            if (cs == NULL) {
                                return;
                            }
                            if (cs->left) {
                                if (frame->action.field != GAS_COMEBACK_REQUEST) {
                                    fprintf(stderr, "in the middle of fragmenting got a %s\n",
                                            frame->action.field == GAS_INITIAL_REQUEST ? "GAS Initial Request" : \
                                            frame->action.field == GAS_INITIAL_RESPONSE ? "GAS Initial Response" : \
                                            "GAS Comeback Response");
                                    return;
                                }
                                printf("sending next fragment, %d left\n", cs->left);
                                cons_next_fragment(cs);
                            } else {
                                srv_rem_timeout(srvctx, cs->t);
                                tcpbuflen = htonl(left+1);
                                memcpy(tocontroller, (unsigned char *)&tcpbuflen, sizeof(uint32_t));
                                memcpy(tocontroller + sizeof(uint32_t),
                                       (unsigned char *)&frame->action.field, left+1);

                                printf("sending %d byte message from " MACSTR " back to controller...\n\n",
                                       left+1, MAC2STR(cs->peeraddr));
                                print_buffer("message", tocontroller, left+1+sizeof(uint32_t));
                                if (write(cs->fd, (unsigned char *)tocontroller, left+1+sizeof(uint32_t)) < 1) {
                                    fprintf(stderr, "relay: unable to send length of message to controller!\n");
                                }
                                printf("sent message to controller!\n");
                                cs->t = srv_add_timeout(srvctx, SRV_SEC(10), delete_cstate, cs);
                            }
                            break;
                        default:
                            printf("unknown action frame %d\n", frame->action.field);
                            break;
                    }
            }
        }
        /*
         * there might be another frame...
         */
        len -= BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
        ptr += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
    }
}

/*
 * fin()
 *      sae has finished for the specified MAC address. If the reason
 *      is because it was successful, there will be a key (PMK) to plumb
 */
void
fin (unsigned short reason, unsigned char *mac, unsigned char *key, int keylen)
{
    printf("status of " MACSTR " is %d, ", MAC2STR(mac), reason);
    if ((reason == 0) && (key != NULL) && (keylen > 0)) {
        printf("plumb the %d byte key into the kernel now!\n", keylen);
    } else {
        printf("(an error)\n");
    }
}

static void
add_interface (char *ptr)
{
    struct interface *inf;
    char bpfdev[sizeof "/dev/bpfXXXXXXXX"];
    int s, var, bpfnum = 0;
    struct ifreq ifr;
    struct bpf_program bpf_filter;
    struct bpf_insn allofit[] = {
        /*
         * a bpf filter to get beacons, authentication and action frames 
         */
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80, 0, 1),    /* beacon */
        BPF_STMT(BPF_RET+BPF_K, (unsigned int) -1),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xb0, 0, 1),    /* auth */
        BPF_STMT(BPF_RET+BPF_K, (unsigned int) -1),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xd0, 0, 1),    /* action  */
        BPF_STMT(BPF_RET+BPF_K, (unsigned int) -1),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };
    struct bpf_insn sim80211[] = {
        /*
         * for loopback interfaces, just grab everything
         */
        { 0x6, 0, 0, 0x00000800 },
    };

    TAILQ_FOREACH(inf, &interfaces, entry) {
        if (memcmp(&inf->ifname, ptr, strlen(ptr)) == 0) {
            printf("%s is already on the list!\n", ptr);
            return;
        }
    }
    if ((inf = (struct interface *)malloc(sizeof(struct interface))) == NULL) {
        fprintf(stderr, "failed to malloc space for new interface %s!\n", ptr);
        return;
    }
    strncpy(inf->ifname, ptr, strlen(ptr));

    /*
     * see if this is a loopback interface
     */
    if ((s = socket(PF_INET, SOCK_RAW, 0)) < 0) {
        fprintf(stderr, "unable to get raw socket to determine interface flags!\n");
        return;
    }
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, inf->ifname, IFNAMSIZ);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "unable to get ifflags for %s!\n", ptr);
        /*
         * should this be fatal? Dunno, let's just assume it's _not_ loopback
         */
        ifr.ifr_flags = 0;
    }
    close(s);
    if (ifr.ifr_flags & IFF_LOOPBACK) {
        inf->is_loopback = 1;
    }
    /*
     * find a non-busy bpf device
     */
    do {
        (void)snprintf(bpfdev, sizeof(bpfdev), "/dev/bpf%d", bpfnum++);
        inf->fd = open(bpfdev, O_RDWR);
    } while (inf->fd < 0 && errno == EBUSY);
    if (inf->fd < 0) {
        fprintf(stderr, "error opening bpf device %s!\n", bpfdev);
        perror("open");
        exit(1);
    }

    var = 2048;
    if (ioctl(inf->fd, BIOCSBLEN, &var)) {
        fprintf(stderr, "can't set bpf buffer length!\n");
        exit(1);
    }
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, inf->ifname, IFNAMSIZ);
    printf("setting bpf%d to interface %s, %s\n", bpfnum-1, ifr.ifr_name,
           inf->is_loopback ? "loopback" : "not loopback");
    if (ioctl(inf->fd, BIOCSETIF, &ifr)) {
        fprintf(stderr, "unable to set bpf!\n");
        exit(1);
    }
    if (ioctl(inf->fd, BIOCPROMISC, &ifr)) {
        fprintf(stderr, "can't set bpf to be promiscuous!\n");
        exit(1);
    }
    var = 1;
    if (ioctl(inf->fd, BIOCIMMEDIATE, &var)) {
        fprintf(stderr, "can't set bpf to be immediate!\n");
        exit(1);
    }
    var = 0;
    if (ioctl(inf->fd, BIOCSSEESENT, &var)) {
        fprintf(stderr, "can't tell bpf to ignore our own packets!\n");
        /* not really fatal, just bothersome */
    }
    if (inf->is_loopback) {
        /*
         * make up a bssid for the loopback interface
         */
        RAND_bytes(&inf->bssid[0], ETH_ALEN);
        var = DLT_NULL;
        if (ioctl(inf->fd, BIOCSDLT, &var)) {
            fprintf(stderr, "can't set bpf link layer type!\n");
            exit(1);
        }
        bpf_filter.bf_len = sizeof(sim80211) / sizeof(struct bpf_insn);
        bpf_filter.bf_insns = sim80211;
        if (ioctl(inf->fd, BIOCSETF, &bpf_filter)) {
            fprintf(stderr, "can't set bpf filter!\n");
            perror("ioctl setting bpf filter");
            exit(1);
        }
    } else {
        var = DLT_IEEE802_11;
        if (ioctl(inf->fd, BIOCSDLT, &var)) {
            fprintf(stderr, "can't set bpf link layer type!\n");
            exit(1);
        }
        var = 1;
        if (ioctl(inf->fd, BIOCSHDRCMPLT, &var)) {
            fprintf(stderr, "can't tell bpf we are doing our own headers!\n");
            exit(1);
        }
        bpf_filter.bf_len = sizeof(allofit) / sizeof(struct bpf_insn);
        bpf_filter.bf_insns = allofit;
        if (ioctl(inf->fd, BIOCSETF, &bpf_filter)) {
            fprintf(stderr, "can't set bpf filter!\n");
            perror("ioctl setting bpf filter");
            exit(1);
        }
    }
    srv_add_input(srvctx, inf->fd, inf, bpf_in);
    TAILQ_INSERT_TAIL(&interfaces, inf, entry);

    return;
}

static unsigned long
chan2freq (unsigned int chan)
{
    if (chan == 14) {
        return 2484;
    }
    if (chan < 14) {
        return 2407 + chan * 5;
    }
    if (chan < 27) {
        return 2512 + ((chan - 15)*20);
    }
    return 5000 + (chan * 5);
}

int
change_channel (unsigned char *mymac, unsigned char class, unsigned char channel)
{
    int i, s, maxregs, thechan, band;
    unsigned int freq;
    struct ieee80211req ireq;
    struct ifmediareq ifmreq;
    struct ieee80211req_chaninfo chans;
    struct interface *inf;

    /*
     * find the interface whose radio we're gonna muck with
     */
    TAILQ_FOREACH(inf, &interfaces, entry) {
        if (memcmp(mymac, inf->bssid, ETH_ALEN) == 0) {
            break;
        }
    }
    if (inf == NULL) {
        fprintf(stderr, "can't find " MACSTR " to change channel!\n",
                MAC2STR(mymac));
        return -1;
    }
    /*
     * if loopback just say the channel was changed...
     */
    if (inf->is_loopback) {
        return 1;
    }

    if ((s = socket(PF_INET, SOCK_RAW, 0)) < 0) {
        fprintf(stderr, "unable to get raw socket to determine interface flags!\n");
        return -1;
    }
    /*
     * find if the global operating class/channel is supported
     */
    maxregs = (sizeof(regulatory)/sizeof(struct _regulatory));
    for (i = 0; i < maxregs; i++) {
        if ((regulatory[i].class == class) && (regulatory[i].channel == channel)) {
            thechan = regulatory[i].channel;
            band = regulatory[i].band;
            break;
        }
    }
    if (i == maxregs) {
        close(s);
        return -1;
    }
    /*
     * figure out what channels are allowable on this radio
     */
    memset(&ireq, 0, sizeof(ireq));
    strlcpy(ireq.i_name, inf->ifname, IFNAMSIZ);
    ireq.i_type = IEEE80211_IOC_CHANINFO;
    ireq.i_data = &chans;
    ireq.i_len = sizeof(chans);
    if (ioctl(s, SIOCG80211, &ireq) < 0) {
        fprintf(stderr, "unable to get available channels!\n");
        close(s);
        return -1;
    }

    freq = chan2freq(thechan);
    for (i = 0; i < chans.ic_nchans; i++) {
        /*
         * go through them all, ignore if not in the configured band 
         */
        if (IEEE80211_IS_CHAN_A(&chans.ic_chans[i]) && (band != RADIO_11a)) {
            continue;
        }
        if (!IEEE80211_IS_CHAN_A(&chans.ic_chans[i]) && (band == RADIO_11a)) {
            continue;
        }
        if (freq == chans.ic_chans[i].ic_freq) {
            break;
        }
    }
    if (i == chans.ic_nchans) {
        fprintf(stderr, "invalid channel, %d, for band %s\n", thechan,
                band == RADIO_11a ? "11a" : band == RADIO_11b ? "11b" : "11g");
        close(s);
        return -1;
    }
    /*
     * we have an acceptable channel/band and the radio supports it!
     *
     * Get the media options
     */
    memset(&ifmreq, 0, sizeof(ifmreq));
    strlcpy(ifmreq.ifm_name, inf->ifname, IFNAMSIZ);
    if (ioctl(s, SIOCGIFMEDIA, &ifmreq) < 0) {
        fprintf(stderr, "unable to get mediaopt!\n");
        close(s);
        return -1;
    }
    ifmreq.ifm_current &= ~(IFM_IEEE80211_11A | IFM_IEEE80211_11B | IFM_IEEE80211_11G | IFM_IEEE80211_FH);
    /*
     * possible change the band...
     */
    switch (band) {
        case RADIO_11a:
            ifmreq.ifm_current |= IFM_IEEE80211_11A;
            break;
        case RADIO_11b:
            ifmreq.ifm_current |= IFM_IEEE80211_11B;
            break;
        case RADIO_11g:
            ifmreq.ifm_current |= IFM_IEEE80211_11G;
            break;
        default:
            /* should not happen! famous last words... */
            close(s);
            return -1;
    }
    if (ioctl(s, SIOCSIFMEDIA, &ifmreq) < 0) {
        fprintf(stderr, "unable to set mediaopt!\n");
        perror("ioctl");
        close(s);
        return -1;
    }
    /*
     * now change the channel
     */
    memset(&ireq, 0, sizeof(ireq));
    strlcpy(ireq.i_name, inf->ifname, IFNAMSIZ);
    ireq.i_type = IEEE80211_IOC_CHANNEL;
    ireq.i_val = thechan;
    if (ioctl(s, SIOCS80211, &ireq) < 0) {
        fprintf(stderr, "unable to set channel %d for band %s\n", thechan,
                band == RADIO_11a ? "11a" : band == RADIO_11b ? "11b" : "11g");
        close(s);
        return -1;
    }
    printf("setting to channel %d, global operating class %d\n", channel, class);
    close(s);
    return 1;
}

void
new_controller (int fd, void *data)
{
    struct sockaddr_in *serv = (struct sockaddr_in *)data;
    int sd, len, rlen;
    unsigned int clen;
    struct cstate *cs;
    unsigned char broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    struct interface *inf;
    char buf[3000];
    TLV *tlv;
    uint32_t netlen;
    dpp_action_frame *frame;
    struct wired_control *ctrl;
  
    printf("new controller!!!\n");
    clen = sizeof(struct sockaddr_in);
    if ((sd = accept(fd, (struct sockaddr *)serv, &clen)) < 0) {
        fprintf(stderr, "failed to accept new connection from controller!\n");
        return;
    }
    
    if ((cs = (struct cstate *)malloc(sizeof(struct cstate))) == NULL) {
        close(sd);
        fprintf(stderr, "failed to create connection from controller!\n");
        return;
    }
    memset(cs, 0, sizeof(struct cstate));
    cs->fd = sd;

    if (read(cs->fd, (char *)&netlen, sizeof(uint32_t)) < 0) {
        close(sd);
        free(cs);
        return;
    }
    netlen = ntohl(netlen);

    len = 0;
    while (netlen) {
        if ((rlen = read(cs->fd, (buf + len), netlen)) < 1) {
            fprintf(stderr, "unable to read message from new controller\n");
            close(sd);
            free(cs);
            return;
        }
        len += rlen;
        netlen -= rlen;
    }

    /*
     * if the controller has more than just the bootstrapping key then we get
     * that stuff first in a wired control message (field = -1)
     */
    if (buf[0] == -1) {
        if (len < sizeof(struct wired_control)) {
            return;
        }
        ctrl = (struct wired_control *)&buf[1];
        printf("received notification of enrollee at " MACSTR " on %d/%d\n",
               MAC2STR(ctrl->peermac), ctrl->opclass, ctrl->channel);

        memcpy(cs->peeraddr, ctrl->peermac, ETH_ALEN);
        /*
         * TODO: figure out how to identify the right interface 
         */
        memcpy(cs->myaddr, ((struct interface *)TAILQ_FIRST(&interfaces))->bssid, ETH_ALEN);
        change_channel(((struct interface *)TAILQ_FIRST(&interfaces))->bssid, ctrl->opclass, ctrl->channel);

        TAILQ_INSERT_TAIL(&cstates, cs, entry);
        /*
         * the request is forthcoming, so just sit back and wait for it...
         */
        srv_add_input(srvctx, cs->fd, cs, message_from_controller);
        /*
         * but set a timer to delete it if nothing is actually forthcoming
         */
        cs->t = srv_add_timeout(srvctx, SRV_SEC(10), delete_cstate, cs);
        return;
    } else {
        memcpy(cs->peeraddr, broadcast, ETH_ALEN);
    }
    
    /*
     * this has to either be a DPP auth request or a PKEX exchange request
     */
    if (buf[0] != PUB_ACTION_VENDOR) {
        fprintf(stderr, "first message from controller not a DPP/PKEX request!\n");
        close(sd);
        free(cs);
        return;
    }
    frame = (dpp_action_frame *)&buf[1];
    switch (frame->frame_type) {
        /*
         * grab the hash of the peer's bootstrapping key to match up this
         * conversation when we get the AUTH_RESPONSE back
         */
        case DPP_SUB_AUTH_REQUEST:
            tlv = (TLV *)frame->attributes;
            memcpy(cs->bkhash, tlv->value, SHA256_DIGEST_LENGTH);
            break;
        case PKEX_SUB_EXCH_REQ:
            tlv = (TLV *)frame->attributes;
            tlv = TLV_next(tlv);        // see if there's an identifier
            if (TLV_type(tlv) == TRANSACTION_IDENTIFIER) {
                memcpy(cs->bkhash, tlv->value,
                       TLV_length(tlv) < SHA256_DIGEST_LENGTH ? TLV_length(tlv) : SHA256_DIGEST_LENGTH);
            }
            break;
        default:
            fprintf(stderr, "first message from controller not a DPP/PKEX request!\n");
            close(sd);
            free(cs);
            return;
    }
    /*
     * since we don't know where the peer is, send this out to all our interfaces.
     * -1 because the first byte read was PUB_ACTION_VENDOR
     */
    TAILQ_FOREACH(inf, &interfaces, entry) {
        cons_action_frame(PUB_ACTION_VENDOR, inf->bssid, broadcast, &buf[1], len - 1);
    }
    TAILQ_INSERT_TAIL(&cstates, cs, entry);
    
    srv_add_input(srvctx, cs->fd, cs, message_from_controller);
    /*
     * set a timer to delete this if we don't ever get a response
     */
    cs->t = srv_add_timeout(srvctx, SRV_SEC(10), delete_cstate, cs);

    return;
}

static void
compute_bk_hash (struct interface *inf, char *bkfile)
{
    FILE *fp;
    int asn1len;
    EVP_MD_CTX *mdctx;
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
    unsigned char asn1[2048], keyb64[1024];
    int i;
                
    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        fprintf(stderr, "can't create an MD context!\n");
        return;
    }
    memset(keyb64, 0, 1024);
    memset(asn1, 0, 2048);
    if ((fp = fopen(bkfile, "r")) == NULL) {
        fprintf(stderr, "unable to open %s as bootstrap key file\n", bkfile);
        return;
    }
    if (fscanf(fp, "%s", keyb64) < 0) {
        fprintf(stderr, "unable to read bootstrap key file %s\n", bkfile);
        return;
    }
    fclose(fp);

    if ((asn1len = EVP_DecodeBlock(asn1, (unsigned char *)keyb64, strlen(keyb64))) < 0) {
        fprintf(stderr, "unable to decode public key from bootstrap key file %s\n", bkfile);
        return;
    }
    asn1len--;

    printf("bootstrapping key:\n");
    for (i=0;i<asn1len;i++) printf("%02x", asn1[i]);
    printf("\n");

    EVP_DigestInit(mdctx, EVP_sha256());
    EVP_DigestUpdate(mdctx, asn1, asn1len);
    EVP_DigestFinal(mdctx, inf->bkhash, &mdlen);

    EVP_MD_CTX_free(mdctx);
    return;
}

int
main (int argc, char **argv)
{
    int s, c, got_controller = 0, infd, opt, mediaopt;
    int mib[6];
    size_t needed;
    struct interface *inf;
    char interface[10], bkfile[30], *cruft, ssid[32];
    struct sockaddr_in serv;
    struct ifmediareq ifmreq;
    struct ieee80211req ireq;
    struct ifreq ifr;
    struct if_msghdr *ifm;
    struct sockaddr_dl *sdl;

    if ((srvctx = srv_create_context()) == NULL) {
        fprintf(stderr, "%s: cannot create service context!\n", argv[0]);
        exit(1);
    }
    TAILQ_INIT(&interfaces);
    TAILQ_INIT(&cstates);
    mediaopt = RADIO_ADHOC;
    opclass = 81;
    channel = 6;
    strcpy(ssid, "blahblahblah");
    portin = 8741;
    portout = DPP_PORT;
    
    for (;;) {
        c = getopt(argc, argv, "hI:df:g:C:b:s:i:o:");
        if (c < 0) {
            break;
        }
        switch (c) {
            case 'I':           /* interface */
                strcpy(interface, optarg);
                printf("adding interface %s...\n", interface);
                add_interface(interface);
                break;
            case 'd':           /* debug */
//                debug = atoi(optarg);
                break;
            case 'f':           /* channel */
                channel = atoi(optarg);
                break;
            case 'g':           /* operating class */
                opclass = atoi(optarg);
                break;
            case 'C':
                got_controller = 1;
                strcpy(controller, optarg);
                break;
            case 'b':
                strcpy(bkfile, optarg);
                break;
            case 's':
                strcpy(ssid, optarg);
                break;
            case 'i':
                portin = atoi(optarg);
                break;
            case 'o':
                portout = atoi(optarg);
                break;
            default:
            case 'h':
                fprintf(stderr, 
                        "USAGE: %s [-hCIBapkceirdfgs]\n"
                        "\t-h  show usage, and exit\n"
                        "\t-I <interface> to add to DPP\n"
                        "\t-C <controller> to whom DPP frames are sent\n"
                        "\t-b <filename> of controller's bootstrapping key\n"
                        "\t-f <channel> to use with DPP\n"
                        "\t-g <opclass> operating class to use with DPP\n"
                        "\t-i <num> port number for inbound (default 8741)\n"
                        "\t-o <num> port number for outbound (default 8908)\n"
                        "\t-d <debug> set debugging mask\n",
                        argv[0]);
                exit(1);
                
        }
    }
    if (!got_controller) {
        fprintf(stderr, "%s: need to specify a controller with -C\n", argv[0]);
        exit(1);
    }
    if (TAILQ_EMPTY(&interfaces)) {
        fprintf(stderr, "%s: no interfaces defined!\n", argv[0]);
        add_interface("lo");
    }
    printf("interfaces and MAC addresses:\n");
    TAILQ_FOREACH(inf, &interfaces, entry) {
        if (inf->is_loopback) {
            /*
             * no radio to configure
             */
            printf("\t%s: " MACSTR "\n", inf->ifname, MAC2STR(inf->bssid));
        } else {
            if ((s = socket(PF_INET, SOCK_RAW, 0)) < 0) {
                fprintf(stderr, "unable to get raw socket to determine interface flags!\n");
                exit(1);
            }
            /*
             * get the link-layer address of the interface and make that
             * the radio's bssid
             */
            memset(&ifr, 0, sizeof(ifr));
            strlcpy(ifr.ifr_name, inf->ifname, IFNAMSIZ);
            if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
                fprintf(stderr, "%s: cannot determine ifindex!\n", argv[0]);
                exit(1);
            }
            mib[0] = CTL_NET;
            mib[1] = PF_ROUTE;
            mib[2] = 0;
            mib[3] = 0;
            mib[4] = NET_RT_IFLIST;
            mib[5] = ifr.ifr_index;
            if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
                fprintf(stderr, "%s: cannot determine size of info from sysctl!\n", argv[0]);
                exit(1);
            }
            if ((cruft = malloc(needed)) == NULL) {
                fprintf(stderr, "%s: cannot malloc space to retrieve sysctl info!\n", argv[0]);
                exit(1);
            }
            if (sysctl(mib, 6, cruft, &needed, NULL, 0) < 0) {
                free(cruft);
                fprintf(stderr, "%s: cannot obtain info from sysctl!\n", argv[0]);
                exit(1);
            }
            ifm = (struct if_msghdr *)cruft;
            if (ifm->ifm_type != RTM_IFINFO) {
                fprintf(stderr, "%s: unexpected result from sysctl, expected %d got %d\n",
                        argv[0], RTM_IFINFO, ifm->ifm_type);
                exit(1);
            }
            if (ifm->ifm_data.ifi_datalen == 0) {
                ifm->ifm_data.ifi_datalen = sizeof(struct if_data);
            }
            sdl = (struct sockaddr_dl *)((char *)ifm + sizeof(struct if_msghdr) - sizeof(struct if_data) + ifm->ifm_data.ifi_datalen);
            memcpy(inf->bssid, LLADDR(sdl), ETH_ALEN);
            free(cruft);

            memset(&ireq, 0, sizeof(struct ieee80211req));
            strlcpy(ireq.i_name, inf->ifname, IFNAMSIZ);
            ireq.i_type = IEEE80211_IOC_BSSID;
            ireq.i_len = ETH_ALEN;
            ireq.i_data = inf->bssid;
            if (ioctl(s, SIOCS80211, &ireq) < 0) {
                fprintf(stderr, "%s: unable to set bssid!\n", argv[0]);
                perror("ioctl setting bssid");
                exit(1);
            }
            printf("\t%s: " MACSTR "\n", inf->ifname, MAC2STR(inf->bssid));
            /*
             * enable RSN
             */
            memset(&ireq, 0, sizeof(struct ieee80211req));
            strlcpy(ireq.i_name, inf->ifname, IFNAMSIZ);
            ireq.i_type = IEEE80211_IOC_WPA;
            ireq.i_val = 6;     /* DPP + DPP Configurator Connectivity IE */
            if (ioctl(s, SIOCS80211, &ireq) < 0) {
                fprintf(stderr, "%s: unable to set RSN!\n", argv[0]);
                perror("ioctl setting RSN");
                exit(1);
            }
            /*
             * enable privacy
             */
            memset(&ireq, 0, sizeof(struct ieee80211req));
            strlcpy(ireq.i_name, inf->ifname, IFNAMSIZ);
            ireq.i_type = IEEE80211_IOC_PRIVACY;
            ireq.i_val = 1;
            if (ioctl(s, SIOCS80211, &ireq) < 0) {
                fprintf(stderr, "%s: unable to enable privacy!\n", argv[0]);
                perror("ioctl setting privacy bit");
                exit(1);
            }
            /*
             * enable DPP RSN for beacons
             */
            memset(&ireq, 0, sizeof(struct ieee80211req));
            strlcpy(ireq.i_name, inf->ifname, IFNAMSIZ);
            ireq.i_type = IEEE80211_IOC_KEYMGTALGS;
            ireq.i_val = 0x80;  /* not the real one but it's what we use */
            if (ioctl(s, SIOCS80211, &ireq) < 0) {
                fprintf(stderr, "unable to set DPP!\n");
                perror("ioctl setting DPP");
                exit(1);
            }
            /*
             * use CCMP for ucast
             */
            memset(&ireq, 0, sizeof(struct ieee80211req));
            strlcpy(ireq.i_name, inf->ifname, IFNAMSIZ);
            ireq.i_type = IEEE80211_IOC_UCASTCIPHERS;
            ireq.i_val = 0x08;
            if (ioctl(s, SIOCS80211, &ireq) < 0) {
                fprintf(stderr, "unable to set mcast to CCMP!\n");
                perror("ioctl setting mcast to CCMP");
                exit(1);
            }
            /*
             * use CCMP for mcast
             */
            memset(&ireq, 0, sizeof(struct ieee80211req));
            strlcpy(ireq.i_name, inf->ifname, IFNAMSIZ);
            ireq.i_type = IEEE80211_IOC_MCASTCIPHER;
            ireq.i_val = 3;
            if (ioctl(s, SIOCS80211, &ireq) < 0) {
                fprintf(stderr, "unable to set mcast to CCMP!\n");
                perror("ioctl setting mcast to CCMP");
                exit(1);
            }
            /*
             * set the SSID
             */
            memset(&ireq, 0, sizeof(struct ieee80211req));
            strlcpy(ireq.i_name, inf->ifname, IFNAMSIZ);
            ireq.i_type = IEEE80211_IOC_SSID;
            ireq.i_data = ssid;
            ireq.i_len = strlen(ssid);

            if (ioctl(s, SIOCS80211, &ireq) < 0) {
                fprintf(stderr, "unable to set SSID!\n");
                perror("ioctl");
                return -1;
            }

            /*
             * set the media option
             */
            memset(&ifmreq, 0, sizeof(ifmreq));
            strlcpy(ifmreq.ifm_name, inf->ifname, IFNAMSIZ);
            if (ioctl(s, SIOCGIFMEDIA, &ifmreq) < 0) {
                fprintf(stderr, "%s: unable to get mediaopt!\n", argv[0]);
                exit(1);
            }
            switch (mediaopt) {
                case RADIO_STA:
                    ifmreq.ifm_current &= ~(IFM_IEEE80211_HOSTAP | IFM_IEEE80211_MONITOR | IFM_IEEE80211_ADHOC | IFM_IEEE80211_IBSS);
                    break;
                case RADIO_ADHOC:
                    ifmreq.ifm_current &= ~(IFM_IEEE80211_HOSTAP | IFM_IEEE80211_MONITOR | IFM_IEEE80211_IBSS);
                    ifmreq.ifm_current |= IFM_IEEE80211_ADHOC;
                    break;
                case RADIO_HOSTAP:
                    ifmreq.ifm_current &= ~(IFM_IEEE80211_MONITOR | IFM_IEEE80211_ADHOC | IFM_IEEE80211_IBSS);
                    ifmreq.ifm_current |= IFM_IEEE80211_HOSTAP;
                    break;
                case RADIO_MONITOR:
                    ifmreq.ifm_current &= ~(IFM_IEEE80211_HOSTAP | IFM_IEEE80211_ADHOC | IFM_IEEE80211_IBSS);
                    ifmreq.ifm_current |= IFM_IEEE80211_MONITOR;
                    break;
                case RADIO_IBSS:
                    ifmreq.ifm_current &= ~(IFM_IEEE80211_HOSTAP | IFM_IEEE80211_ADHOC | IFM_IEEE80211_MONITOR);
                    ifmreq.ifm_current |= IFM_IEEE80211_IBSS;
                    break;
            }

            if (ioctl(s, SIOCSIFMEDIA, &ifmreq) < 0) {
                fprintf(stderr, "%s: unable to set mediaopt!\n", argv[0]);
                perror("ioctl");
                exit(1);
            }
            /*
             * set the indicated channel and band now if we're not supposed
             * to do in mid-DPP exchange
             */
            printf("setting opclass %d and channel %d\n", opclass, channel);
            if (change_channel(inf->bssid, opclass, channel) < 0) {
                fprintf(stderr, "%s: operating class/channel of %d/%d is not supported!\n",
                        argv[0], opclass, channel);
                exit(1);
            }
            /*
             * finally let's make sure the interface is up
             */
            if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
                fprintf(stderr, "%s: cannot get ifflags for %s\n", argv[0], inf->ifname);
                exit(1);
            }
            if ((ifr.ifr_flags & IFF_UP) == 0) {
                ifr.ifr_flags |= IFF_UP;
                if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
                    fprintf(stderr, "%s: can't set %s to UP!\n", argv[0], inf->ifname);
                }
            }
            close(s);
        }
        compute_bk_hash(inf, bkfile);
    }
    printf("controller is at %s\n", controller);

    /*
     * create and bind listening socket for new DPP conversations started
     * by the controller
     */
    if ((infd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "%s: unable to create inbound TCP socket!\n", argv[0]);
        exit(1);
    }
    opt = 1;
    if (setsockopt(infd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)) < 0) {
        fprintf(stderr, "%s: unable to set TCP socket to reuse addr!\n", argv[0]);
        exit(1);
    }
    
    memset((char *)&serv, 0, sizeof(struct sockaddr_in));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = INADDR_ANY;
    serv.sin_port = htons(portin);
    if ((bind(infd, (struct sockaddr *)&serv, sizeof(struct sockaddr_in)) < 0) ||
        (listen(infd, 0) < 0)) {
        fprintf(stderr, "%s: unable to bind/listen TCP socket!\n", argv[0]);
        exit(1);
    }
    srv_add_input(srvctx, infd, &serv, new_controller);

    srv_main_loop(srvctx);

    exit(1);
}
