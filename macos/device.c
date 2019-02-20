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
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include "ieee802_11.h"
#include "service.h"
#include "common.h"
#include "tlv.h"
#include "pkex.h"
#include "dpp.h"

service_context srvctx;
unsigned int opclass = 81, channel = 6;
char controller[30], bootstrapfile[80];
int fd;
unsigned char myfakemac[ETH_ALEN] = { 0xde, 0xad, 0xbe, 0xef, 0xf0, 0x00 };
unsigned char peerfakemac[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
dpp_handle handle;

/*
 * cons up the body of an action frame and send it out to the controller
 */
static int
cons_action_frame (unsigned char field, char *data, int len)
{
    char buf[2048], *ptr;
    uint32_t netlen;

    memset(buf, 0, sizeof(buf));
    ptr = buf;
    
    netlen = htonl(len + 1);
    memcpy(ptr, (char *)&netlen, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    *ptr = field;
    ptr++;
    
    memcpy(ptr, data, len);

    if (write(fd, buf, len + 1 + sizeof(uint32_t)) < 1) {
        fprintf(stderr, "can't send message to controller!\n");
        return -1;
    }
    return len;
}

/*
 * wrappers to send action frames
 */
int
transmit_config_frame (dpp_handle unused, unsigned char field, char *data, int len)
{
    return cons_action_frame(field, data, len);
}

int
transmit_auth_frame (dpp_handle unused, char *data, int len)
{
    return cons_action_frame(PUB_ACTION_VENDOR, data, len);
}

int
transmit_discovery_frame (unsigned char tid, char *data, int len)
{
    return cons_action_frame(PUB_ACTION_VENDOR, data, len);
}

int
transmit_pkex_frame (unsigned char *mymac, unsigned char *peermac, char *data, int len)
{
/* don't do PKEX yet
    return cons_action_frame(PUB_ACTION_VENDOR, mymac, peermac, data, len);
*/
    return 1;
}

static int
process_incoming_mgmt_frame(unsigned char type, unsigned char *msg, int len)
{
    dpp_action_frame *dpp;

    switch (type) {
        case PUB_ACTION_VENDOR:
            /* 
             * PKEX, DPP Auth, and DPP Discovery
             */
            dpp = (dpp_action_frame *)msg;
            printf("pub action vendor frame...\n");
            switch (dpp->frame_type) {
                /*
                 * DPP Auth
                 */
                case DPP_SUB_AUTH_REQUEST:
                case DPP_SUB_AUTH_RESPONSE:
                case DPP_SUB_AUTH_CONFIRM:
                    printf("DPP Authentication frame...\n");
                    if (process_dpp_auth_frame(msg, len, handle) < 0) {
                        fprintf(stderr, "error processing DPP Auth frame!\n");
                        return -1;
                    }
                    break;
                case DPP_SUB_PEER_DISCOVER_REQ:
                case DPP_SUB_PEER_DISCOVER_RESP:
                    /*
                     * device doesn't send or receive DPP discovery frames
                     */
                    break;
                case PKEX_SUB_EXCH_REQ:
                case PKEX_SUB_COM_REV_REQ:
                case PKEX_SUB_COM_REV_RESP:
                case PKEX_SUB_EXCH_RESP:
                    printf("PKEX frame...\n");
/* don't do PKEX yet
                    if (process_pkex_frame(msg, len, mymac, peermac) < 0) {
                        fprintf(stderr, "error processing PKEX frame!\n");
                        return -1;
                    }
*/
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
            printf("GAS frame...\n");
            if (process_dpp_config_frame(type, msg, len, handle) < 0) {
                fprintf(stderr, "error processing DPP Config frame!\n");
                return -1;
            }
            break;
        default:
            printf("unknown DPP/PKEX management frame...\n");
            break;
    }
    return 1;
}

void
message_from_controller (int ifd, void *data)
{
    unsigned char buf[3000];
    uint32_t netlen;
    int len, rlen;

    if (read(ifd, (char *)&netlen, sizeof(uint32_t)) < 0) {
        fprintf(stderr, "unable to read message from controller!\n");
        srv_rem_input(srvctx, ifd);
        close(ifd);
        return;
    }
    netlen = ntohl(netlen);
    if (netlen > sizeof(buf)) {
        fprintf(stderr, "overflow attack by controller! Not gonna read in %d bytes\n",
                netlen);
        srv_rem_input(srvctx, ifd);
        close(ifd);
        return;
    }
        
    len = 0;
    while (netlen) {
        if ((rlen = read(ifd, (buf + len), netlen)) < 1) {
            fprintf(stderr, "unable to read message from controller!\n");
            srv_rem_input(srvctx, ifd);
            close(ifd);
            return;
        }
        len += rlen;
        netlen -= rlen;
    }
    printf("read %d byte message from controller\n", len);
    if (process_incoming_mgmt_frame(buf[0], &buf[1], len - 1) < 1) {
        fprintf(stderr, "unable to send message from controller to peer!\n");
        return;
    }
    return;
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

int
change_channel (unsigned char *blah, unsigned char foo, unsigned char bar)
{
    return 1;
}

int
change_dpp_channel (dpp_handle unused, unsigned char foo, unsigned char bar)
{
    return 1;
}

int
provision_connector (char *role, unsigned char *ssid, int ssidlen,
                     unsigned char *connector, int connlen, dpp_handle handle)
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

int
bootstrap_peer (int keyidx)
{
    FILE *fp;
    int n, opclass, channel;
    unsigned char peermac[ETH_ALEN]; 
    unsigned char keyb64[1024];
    char mac[20], *ptr;

    printf("looking for bootstrap key index %d in %s\n", keyidx, bootstrapfile);
    if ((fp = fopen(bootstrapfile, "r")) == NULL) {
        fprintf(stderr, "failed to open %s to read\n", bootstrapfile);
        return -1;
    }
    while (!feof(fp)) {
        memset(keyb64, 0, sizeof(keyb64));
        fscanf(fp, "%d %d %d %s %s", &n, &opclass, &channel, mac, keyb64);
        if (n == keyidx) {
            break;
        }
    }
    if (feof(fp)) {
        fprintf(stderr, "unable to find bootstrap key with index %d\n", keyidx);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    printf("peer is on operating class %d and channel %d, checking...\n", opclass, channel);
    printf("peer's bootstrapping key is %s\n", keyb64);
    ptr = &mac[10];
    sscanf(ptr, "%hhx", &peermac[5]); mac[10] = '\0';
    ptr = &mac[8];
    sscanf(ptr, "%hhx", &peermac[4]); mac[8] = '\0';
    ptr = &mac[6];
    sscanf(ptr, "%hhx", &peermac[3]); mac[6] = '\0';
    ptr = &mac[4];
    sscanf(ptr, "%hhx", &peermac[2]); mac[4] = '\0';
    ptr = &mac[2];
    sscanf(ptr, "%hhx", &peermac[1]); mac[2] = '\0';
    ptr = &mac[0];
    sscanf(ptr, "%hhx", &peermac[0]); 

    if ((handle = dpp_create_peer(keyb64)) < 1) {
        fprintf(stderr, "unable to create peer!\n");
        return -1;
    }
    
    return 1;
}

int
main (int argc, char **argv)
{
    int debug = 0, c, got_controller = 0, do_pkex = 0, mutual = 1, keyidx = 0, config_or_enroll = 0;
    char password[30], pkexinfo[80], enrollee_role[10], signkeyfile[30];
    char identifier[80], keyfile[80];
    struct sockaddr_in clnt;

    if ((srvctx = srv_create_context()) == NULL) {
        fprintf(stderr, "%s: cannot create service context!\n", argv[0]);
        exit(1);
    }
    memset(bootstrapfile, 0, 80);
    memset(signkeyfile, 0, 30);
    memset(keyfile, 0, 80);
    memset(identifier, 0, 80);
    memset(pkexinfo, 0, 80);
    strcpy(enrollee_role, "sta");
    for (;;) {
        c = getopt(argc, argv, "hd:f:g:C:k:p:ax:B:n:e:c:");
        if (c < 0) {
            break;
        }
        switch (c) {
            case 'd':           /* debug */
                debug = atoi(optarg);
                break;
            case 'B':           /* bootstrap key file */
                strcpy(bootstrapfile, optarg);
                break;
            case 'C':
                got_controller = 1;
                strcpy(controller, optarg);
                break;
            case 'k':           /* keyfile */
                strcpy(keyfile, optarg);
                break;
            case 'p':
                do_pkex = 1;
                strcpy(password, optarg);
                break;
            case 'n':           /* pkex identifier */
                strcpy(identifier, optarg);
                break;
            case 'z':
                strcpy(pkexinfo, optarg);
                break;
            case 'x':
                keyidx = atoi(optarg);
                break;
            case 'a':
                mutual = 0;
                break;
            case 'c':           /* configurator */
                strcpy(signkeyfile, optarg);
                config_or_enroll |= 0x02;
                break;
            case 'e':           /* enrollee */
                strcpy(enrollee_role, optarg);
                config_or_enroll |= 0x01;
                break;
            default:
            case 'h':
                fprintf(stderr, 
                        "USAGE: %s [-hCkpzd]\n"
                        "\t-h  show usage, and exit\n"
                        "\t-C <controller> to whom DPP frames are sent\n"
                        "\t-B <filename> of peer bootstrapping keys\n"
                        "\t-c <signkey> run DPP as the configurator, sign connectors with <signkey>\n"
                        "\t-e <role> run DPP as the enrollee in the role of <role> (sta or ap)\n"
                        "\t-k <keyfile> to use for our key\n"
                        "\t-p <password> for use with PKEX\n"
                        "\t-n <identifier> for the code used in PKEX\n"
                        "\t-z <info> to pass along with public key in PKEX\n"
                        "\t-a to indicate doing non-mutual authentication\n"
                        "\t-x <keyidx> index into bootstrapping key file to use\n"
                        "\t-d <debug> set debugging mask\n",
                        argv[0]);
                exit(1);
                
        }
    }
    if (!got_controller) {
        fprintf(stderr, "%s: need to specify a controller with -C\n", argv[0]);
        exit(1);
    }
    if ((mutual || do_pkex) && (bootstrapfile[0] == 0)) {
        fprintf(stderr, "%s: specify a peer bootstrapping key file with -B <filename>\n", argv[0]);
        exit(1);
    }

    if (!do_pkex && (keyidx == 0)) {
        fprintf(stderr, "%s: either do PKEX or specify an index into bootstrapping file with -x\n",
                argv[0]);
        exit(1);
    }

    printf("connecting to %s\n", controller);
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "%s: unable to create socket!\n", argv[0]);
        exit(1);
    }

    memset((char *)&clnt, 0, sizeof(struct sockaddr_in));
    clnt.sin_family = AF_INET;
    clnt.sin_port = htons(7871);
    if (inet_pton(AF_INET, controller, &clnt.sin_addr) < 0) {
        fprintf(stderr, "%s: unable to set address using inet_pton\n", argv[0]);
        exit(1);
    }
    if (connect(fd, (struct sockaddr *)&clnt, sizeof(struct sockaddr_in)) < 0) {
        close(fd);
        fprintf(stderr, "%s: unable to connect socket to %s\n", argv[0], controller);
        exit(1);
    }
    printf("connected to controller at %s\n", controller);

    srv_add_input(srvctx, fd, NULL, message_from_controller);

    if (do_pkex) {
        if (pkex_initialize(1, password, 
                            identifier[0] == 0 ? NULL : identifier,
                            pkexinfo[0] == 0 ? NULL : pkexinfo, keyfile,
                            bootstrapfile[0] == 0 ? NULL : bootstrapfile, 0, 0, debug) < 0) {
            fprintf(stderr, "%s: cannot configure PKEX/DPP, check config file!\n", argv[0]);
            exit(1);
        }
    }
    if (dpp_initialize(1, config_or_enroll, mutual, keyfile,
                       signkeyfile[0] == 0 ? NULL : signkeyfile, enrollee_role,
                       0, 0, debug) < 0) {
        fprintf(stderr, "%s: cannot configure DPP, check config file!\n", argv[0]);
        exit(1);
    }

    if (!do_pkex) {
        printf("not doing pkex, just DPP...\n");
        bootstrap_peer(keyidx);
    } else {
        printf("PKEX, then DPP...\n");
        pkex_initiate(myfakemac, peerfakemac);
    }

    srv_main_loop(srvctx);

    exit(1);
}
