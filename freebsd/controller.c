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
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/bpf.h>
#include <net/route.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_freebsd.h>
#include <openssl/rand.h>
#include "ieee802_11.h"
#include "service.h"
#include "common.h"
#include "pkex.h"
#include "dpp.h"

struct conversation {
    TAILQ_ENTRY(conversation) entry;
    unsigned char fakepeer[ETH_ALEN];
    int fd;
};
TAILQ_HEAD(bar, conversation) conversations;

service_context srvctx;
char bootstrapfile[80];
unsigned char fakemac[ETH_ALEN] = { 0xde, 0xad, 0xbe, 0xef, 0x0f, 0x00 };
int keyidx = 0;

static void
message_from_relay (int fd, void *data)
{
    struct conversation *conv = (struct conversation *)data;
    dpp_action_frame *dpp;
    unsigned char buf[3000];
    int framesize;

    if ((framesize = read(fd, buf, sizeof(buf))) < 1) {
        fprintf(stderr, "can't read message from relay!\n");
        srv_rem_input(srvctx, fd);
        close(fd);
        TAILQ_REMOVE(&conversations, conv, entry);
        free(conv);
        return;
    }
    printf("read %d byte message from relay!\n", framesize);

    switch (buf[0]) {
        case PUB_ACTION_VENDOR:
            /* 
             * PKEX, DPP Auth, and DPP Discovery
             */
            dpp = (dpp_action_frame *)&buf[1];
            switch (dpp->frame_type) {
                /*
                 * DPP Auth
                 */
                case DPP_SUB_AUTH_REQUEST:
                case DPP_SUB_AUTH_RESPONSE:
                case DPP_SUB_AUTH_CONFIRM:
                    printf("DPP auth message...\n");
                    if (process_dpp_auth_frame(&buf[1], framesize - 1, fakemac, conv->fakepeer) < 0) {
                        fprintf(stderr, "error processing DPP Auth frame from " MACSTR "\n",
                                MAC2STR(conv->fakepeer));
                    }
                    break;
                    /*
                     * DPP Discovery
                     */
                case DPP_SUB_PEER_DISCOVER_REQ:
                case DPP_SUB_PEER_DISCOVER_RESP:
                    printf("DPP discovery message...\n");
                    if (process_dpp_discovery_frame(&buf[1], framesize - 1, fakemac, conv->fakepeer) < 0) {
                        fprintf(stderr, "error processing DPP Discovery frame from " MACSTR "\n",
                                MAC2STR(conv->fakepeer));
                    }
                    break;
                    /*
                     * PKEX
                     */
                case PKEX_SUB_EXCH_REQ:
                case PKEX_SUB_EXCH_RESP:
                case PKEX_SUB_COM_REV_REQ:
                case PKEX_SUB_COM_REV_RESP:
                    printf("PKEX message...\n");
                    if (process_pkex_frame(&buf[1], framesize - 1, fakemac, conv->fakepeer) < 0) {
                        fprintf(stderr, "error processing PKEX frame from " MACSTR "\n",
                                MAC2STR(conv->fakepeer));
                    }
                    break;
                default:
                    fprintf(stderr, "unknown DPP frame %d\n", dpp->frame_type);
                    break;
            }
            break;
        case GAS_INITIAL_REQUEST:
        case GAS_INITIAL_RESPONSE:
        case GAS_COMEBACK_REQUEST:
        case GAS_COMEBACK_RESPONSE:
            /*
             * DPP Configuration protocol
             */
            printf("DPP config message...\n");
            if (process_dpp_config_frame(buf[0], &buf[1], framesize - 1, fakemac, conv->fakepeer) < 0) {
                fprintf(stderr, "error processing DPP Config frame from " MACSTR "\n",
                        MAC2STR(conv->fakepeer));
            }
            break;
        default:
            break;
    }
}

/*
 * cons up an action frame and send it out the conversation
 */
static int
cons_action_frame (unsigned char field, 
                   unsigned char *mymac, unsigned char *peermac, 
                   char *data, int len)
{
    char buf[3000];
    struct conversation *conv = NULL;

    TAILQ_FOREACH(conv, &conversations, entry) {
        fprintf(stderr, "checking whether " MACSTR " matches " MACSTR " to find peer\n",
                MAC2STR(peermac), MAC2STR(conv->fakepeer));
        if (memcmp(peermac, conv->fakepeer, ETH_ALEN) == 0) {
            break;
        }
        fprintf(stderr, "nope!\n");
    }
    if (conv == NULL) {
        fprintf(stderr, "can't find " MACSTR " to send mgmt frame to relay!\n",
                MAC2STR(peermac));
        return -1;
    }
    memset(buf, 0, sizeof(buf));
    buf[0] = field;
    memcpy(&buf[1], data, len < sizeof(buf) ? len : sizeof(buf));

    printf("sending %d byte message to relay\n", len + 1);
    if (write(conv->fd, buf, len + 1) < 1) {
        fprintf(stderr, "can't send message to relay!\n");
        return -1;
    }
    return len;
}

/*
 * wrappers to send action frames
 */
int
transmit_config_frame (unsigned char *mymac, unsigned char *peermac, unsigned char field, char *data, int len)
{
    return cons_action_frame(field, mymac, peermac, data, len);
}

int
transmit_auth_frame (unsigned char *mymac, unsigned char *peermac, char *data, int len)
{
    return cons_action_frame(PUB_ACTION_VENDOR, mymac, peermac, data, len);
}

int
transmit_discovery_frame (unsigned char *mymac, unsigned char *peermac, char *data, int len)
{
    return cons_action_frame(PUB_ACTION_VENDOR, mymac, peermac, data, len);
}

int
transmit_pkex_frame (unsigned char *mymac, unsigned char *peermac, char *data, int len)
{
    return cons_action_frame(PUB_ACTION_VENDOR, mymac, peermac, data, len);
}

int
provision_connector (char *role, unsigned char *ssid, int ssidlen,
                     unsigned char *connector, int connlen, unsigned char *mymac)
{
    printf("connector:\n%.*s\nwith ", connlen, connector);
    if (ssidlen == 1 && ssid[0] == '*') {
        printf("any SSID\n");
    } else {
        printf("SSID %.*s\n", ssidlen, ssid);
    }
    return 1;
}

#if 0
int
save_bootstrap_key (unsigned char *b64key, unsigned char *peermac)
{
    FILE *fp = NULL;
    unsigned char mac[20], existing[1024];
    int ret = -1, oc, ch;
    
    if ((fp = fopen(bootstrapfile, "r+")) == NULL) {
        fprintf(stderr, "SSS: unable to open %s as bootstrapping file\n", bootstrapfile);
        goto fin;
    }
    ret = 0;
    printf("peer's bootstrapping key (b64 encoded)\n%s\n", b64key);
    while (!feof(fp)) {
        memset(existing, 0, 1024);
        if (fscanf(fp, "%d %d %d %s %s", &ret, &oc, &ch, mac, existing) < 1) {
            break;
        }
        if (strcmp((char *)existing, (char *)b64key) == 0) {
            fprintf(stderr, "SSS: bootstrapping key is trusted already\n");
            goto fin;
        }
    }
    ret++;
    /*
     * bootstrapping file is index opclass channel macaddr key
     */
    fprintf(fp, "%d 81 6 %02x%02x%02x%02x%02x%02x %s\n", ret, 
            peermac[0], peermac[1], peermac[2], peermac[3], peermac[4], peermac[5], 
            b64key);
  fin:
    if (fp != NULL) {
        fclose(fp);
    }
    return ret;
}
#endif

void
new_connection (int fd, void *data)
{
    struct sockaddr_in *serv = (struct sockaddr_in *)data;
    struct conversation *conv;
    int sd, rlen, r;
    unsigned int clen;
    unsigned char buf[3000];
    dpp_action_frame *frame;
    
    printf("new connection!!!\n");
    clen = sizeof(struct sockaddr_in);
    if ((sd = accept(fd, (struct sockaddr *)serv, &clen)) < 0) {
        fprintf(stderr, "failed to accept new relay connection!\n");
        return;
    }
    
    if ((conv = (struct conversation *)malloc(sizeof(struct conversation))) == NULL) {
        fprintf(stderr, "unable to create new connectin from relay!\n");
        return;
    }
    memset(conv, 0, sizeof(struct conversation));
    conv->fd = sd;
    r = rand();
    conv->fakepeer[2] = r & 0xff;
    conv->fakepeer[1] = (r >> 8) & 0xff;
    conv->fakepeer[0] = (r >> 16) & 0xff;
    r = rand();
    conv->fakepeer[5] = r & 0xff;
    conv->fakepeer[4] = (r >> 8) & 0xff;
    conv->fakepeer[3] = (r >> 16) & 0xff;

    TAILQ_INSERT_TAIL(&conversations, conv, entry);
    srv_add_input(srvctx, conv->fd, conv, message_from_relay);
    
    if ((rlen = read(conv->fd, buf, sizeof(buf))) < 1) {
        fprintf(stderr, "unable to read message from relay!\n");
        goto fail;
    }
    if (buf[0] != PUB_ACTION_VENDOR) {
        fprintf(stderr, "first message from relay not DPP/PKEX!\n");
        goto fail;
    }
    frame = (dpp_action_frame *)&buf[1];
    switch (frame->frame_type) {
        case PKEX_SUB_EXCH_REQ:
            printf("PKEX request...\n");
            if (process_pkex_frame(&buf[1], rlen - 1, fakemac, conv->fakepeer) < 0) {
                fprintf(stderr, "error processing PKEX frame from relay!\n");
                goto fail;
            }
            break;
        case DPP_SUB_AUTH_REQUEST:
            printf("DPP auth request...\n");
            dpp_create_peer(fakemac, keyidx);
            if (process_dpp_auth_frame(&buf[1], rlen - 1, fakemac, conv->fakepeer) < 0) {
                fprintf(stderr, "error processing DPP auth frame from relay!\n");
                goto fail;
            }
            break;
        default:
            fprintf(stderr, "first message from relay not a DPP/PKEX request!\n");
            goto fail;
    }
    if (0) {
fail:
        close(sd);
        srv_rem_input(srvctx, sd);
        TAILQ_REMOVE(&conversations, conv, entry);
        free(conv);
    }
    return;
}

int
change_channel (unsigned char *blah, unsigned char foo, unsigned char bar)
{
    return 1;
}

int
main (int argc, char **argv)
{
    int c, debug = 0, is_initiator = 0, config_or_enroll = 0, mutual = 1, do_pkex = 0, do_dpp = 1;
    int opt, infd, seed;
    struct sockaddr_in serv;
    char relay[20], password[80], keyfile[80], signkeyfile[80], enrollee_role[10];
    char *ptr, *endptr, identifier[80], pkexinfo[80];
    unsigned char targetmac[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    if ((srvctx = srv_create_context()) == NULL) {
        fprintf(stderr, "%s: cannot create service context!\n", argv[0]);
        exit(1);
    }
    TAILQ_INIT(&conversations);
    memset(bootstrapfile, 0, 80);
    memset(signkeyfile, 0, 80);
    memset(identifier, 0, 80);
    memset(pkexinfo, 0, 80);
//    strcpy(bootstrapfile, "none");
//    strcpy(signkeyfile, "none");
//    strcpy(identifier, "none");
//    strcpy(pkexinfo, "none");
    for (;;) {
        c = getopt(argc, argv, "hirm:k:I:B:x:bae:c:d:p:n:z:");
        if (c < 0) {
            break;
        }
        switch (c) {
            case 'I':           /*  */
                strcpy(relay, optarg);
                break;
            case 'B':           /* bootstrap key file */
                strcpy(bootstrapfile, optarg);
                break;
            case 'k':           /* keyfile */
                strcpy(keyfile, optarg);
                break;
            case 'p':           /* password */
                strcpy(password, optarg);
                do_pkex = 1;
                break;
            case 'n':           /* pkex identifier */
                strcpy(identifier, optarg);
                break;
            case 'd':           /* debug */
                debug = atoi(optarg);
                break;
            case 'i':           /* initiator */
                is_initiator = 1;
                break;
            case 'r':           /* responder */
                is_initiator = 0;
                break;
            case 'c':           /* configurator */
                strcpy(signkeyfile, optarg);
                config_or_enroll |= 0x02;
                do_dpp = 1;
                break;
            case 'e':           /* enrollee */
                strcpy(enrollee_role, optarg);
                config_or_enroll |= 0x01;
                do_dpp = 1;
                break;
            case 'a':           /* not mutual authentication */
                mutual = 0;
                do_dpp = 1;
                break;
            case 'm':
                ptr = optarg;
                targetmac[0] = (unsigned char)strtol(ptr, &endptr, 16); ptr = endptr+1; targetmac[0] &= 0xff;
                targetmac[1] = (unsigned char)strtol(ptr, &endptr, 16); ptr = endptr+1; targetmac[1] &= 0xff;
                targetmac[2] = (unsigned char)strtol(ptr, &endptr, 16); ptr = endptr+1; targetmac[2] &= 0xff;
                targetmac[3] = (unsigned char)strtol(ptr, &endptr, 16); ptr = endptr+1; targetmac[3] &= 0xff;
                targetmac[4] = (unsigned char)strtol(ptr, &endptr, 16); ptr = endptr+1; targetmac[4] &= 0xff;
                targetmac[5] = (unsigned char)strtol(ptr, &endptr, 16); ptr = endptr+1; targetmac[5] &= 0xff;
                break;
            case 'b':
                do_pkex = 1;
                do_dpp = 0;
                break;
            case 'x':
                keyidx = atoi(optarg);
                break;
            case 'z':
                strcpy(pkexinfo, optarg);
                break;
            default:
            case 'h':
                fprintf(stderr, 
                        "USAGE: %s [-hCIBapkceirdfgs]\n"
                        "\t-h  show usage, and exit\n"
                        "\t-c <signkey> run DPP as the configurator, sign connectors with <signkey>\n"
                        "\t-e <role> run DPP as the enrollee in the role of <role> (sta or ap)\n"
                        "\t-i  run DPP as the initiator\n"
                        "\t-r  run DPP as the responder\n"
                        "\t-a  do not perform mutual authentication in DPP\n"
                        "\t-C <filename> of radio configuration file\n"
                        "\t-I <IP address of relay>\n"
                        "\t-B <filename> of peer bootstrappign keys\n"
                        "\t-p <password> to use for PKEX\n"
                        "\t-z <info> to pass along with public key in PKEX\n"
                        "\t-n <identifier> for the code used in PKEX\n"
                        "\t-k <filename> my bootstrapping key\n"
                        "\t-b  bootstrapping (PKEX) only, don't run DPP\n"
                        "\t-x  <index> DPP only with key <index> in -B <filename>, don't do PKEX\n"
                        "\t-m <MAC address> to initiate to, otherwise uses broadcast\n"
                        "\t-d <debug> set debugging mask\n",
                        argv[0]);
                exit(1);
                
        }
    }
    /*
     * if we're doing DPP w/mutual authentication and/or doing PKEX then
     * a bootstrapping key has to be included
     */
    if ((mutual || do_pkex) && (bootstrapfile[0] == 0)) {
        fprintf(stderr, "%s: specify a peer bootstrapping key file with -B <filename>\n", argv[0]);
        exit(1);
    }
    if (is_initiator && !do_pkex && (keyidx == 0)) {
        fprintf(stderr, "%s: either do PKEX or specify an index into bootstrapping file with -x\n",
                argv[0]);
        exit(1);
    }

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
    serv.sin_port = htons(7871);
    if ((bind(infd, (struct sockaddr *)&serv, sizeof(struct sockaddr_in)) < 0) ||
        (listen(infd, 0) < 0)) {
        fprintf(stderr, "%s: unable to bind/listen TCP socket!\n", argv[0]);
        exit(1);
    }
    srv_add_input(srvctx, infd, &serv, new_connection);

    /*
     * initialize data structures...
     */
    if (do_pkex) {
        if (pkex_initialize(is_initiator, password, 
                            identifier[0] == 0 ? NULL : identifier,
                            pkexinfo[0] == 0 ? NULL : pkexinfo, keyfile,
                            bootstrapfile[0] == 0 ? NULL : bootstrapfile, debug) < 0) {
            fprintf(stderr, "%s: cannot configure PKEX/DPP, check config file!\n", argv[0]);
            exit(1);
        }
    }
    if (do_dpp) {
        if (dpp_initialize(is_initiator, config_or_enroll, mutual, keyfile,
                           bootstrapfile[0] == 0 ? NULL : bootstrapfile,
                           signkeyfile[0] == 0 ? NULL : signkeyfile, enrollee_role,
                           0, 0, debug) < 0) {
            fprintf(stderr, "%s: cannot configure DPP, check config file!\n", argv[0]);
            exit(1);
        }
    }
    seed = (int)time(NULL);
    srand(seed);
    
    srv_main_loop(srvctx);

    exit(1);
}
