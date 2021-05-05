/*
 * (c) Copyright 2016, 2017, 2018, 2019 Hewlett Packard Enterprise Development LP
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
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include "ieee802_11.h"
#include "service.h"
#include "common.h"
#include "tlv.h"
#include "pkex.h"
#include "dpp.h"

struct conversation {
    TAILQ_ENTRY(conversation) entry;
    dpp_handle handle;
    int fd;
};
TAILQ_HEAD(bar, conversation) conversations;

service_context srvctx;
char bootstrapfile[80];
int keyidx = 0;

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
delete_conversation (timerid id, void *data)
{
    struct conversation *conv = (struct conversation *)data;

    srv_rem_input(srvctx, conv->fd);
    close(conv->fd);
    TAILQ_REMOVE(&conversations, conv, entry);
    free(conv);
    return;
}

static void
message_from_relay (int fd, void *data)
{
    struct conversation *conv = (struct conversation *)data;
    dpp_action_frame *dpp;
    unsigned char buf[8192], pmk[PMK_LEN], pmkid[PMKID_LEN];
    int framesize, rlen;
    uint32_t netlen;

    if (read(fd, (char *)&netlen, sizeof(uint32_t)) < 0) {
        fprintf(stderr, "can't read message from relay!\n");
        srv_rem_input(srvctx, fd);
        close(fd);
        TAILQ_REMOVE(&conversations, conv, entry);
        free(conv);
        return;
    }
    netlen = ntohl(netlen);
    if ((netlen > sizeof(buf)) || (netlen < 1)) {
        fprintf(stderr, "Not gonna read in %d bytes\n", netlen);
        srv_rem_input(srvctx, fd);
        close(fd);
        TAILQ_REMOVE(&conversations, conv, entry);
        free(conv);
        return;
    }
    
    framesize = 0;
    while (netlen) {
        if ((rlen = read(fd, (buf + framesize), netlen)) < 1) {
            fprintf(stderr, "can't read message from relay!\n");
            srv_rem_input(srvctx, fd);
            close(fd);
            TAILQ_REMOVE(&conversations, conv, entry);
            free(conv);
            return;
        }
        framesize += rlen;
        netlen -= rlen;
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
                    if (process_dpp_auth_frame(&buf[1], framesize - 1, conv->handle) < 0) {
                        fprintf(stderr, "error processing DPP Auth frame\n");
                    }
                    break;
                    /*
                     * DPP Discovery
                     */
                case DPP_SUB_PEER_DISCOVER_REQ:
                    printf("DPP discovery request...\n");
                    if (process_dpp_discovery_frame(&buf[1], framesize - 1,
                                                    (unsigned char)conv->handle, pmk, pmkid) < 0) {
                        fprintf(stderr, "error processing DPP Discovery frame\n");
                    }
                    break;
                case DPP_SUB_PEER_DISCOVER_RESP:
                    /*
                     * shouldn't happen since we don't send DPP discovery requests....
                     */
                    printf("DPP discovery response...\n");
                    if (process_dpp_discovery_frame(&buf[1], framesize - 1,
                                                    (unsigned char)conv->handle, pmk, pmkid) < 0) {
                        fprintf(stderr, "error processing DPP Discovery frame\n");
                    }
                    break;
                    /*
                     * PKEX
                     */
                case PKEX_SUB_EXCH_V1REQ:
                case PKEX_SUB_EXCH_REQ:
                case PKEX_SUB_EXCH_RESP:
                case PKEX_SUB_COM_REV_REQ:
                case PKEX_SUB_COM_REV_RESP:
                    printf("PKEX %s...\n", dpp->frame_type == PKEX_SUB_EXCH_V1REQ ? "exch v1 req" : \
                           dpp->frame_type == PKEX_SUB_EXCH_REQ ? "exch req" : \
                           dpp->frame_type == PKEX_SUB_EXCH_RESP ? "exch resp" : \
                           dpp->frame_type == PKEX_SUB_COM_REV_REQ ? "reveal req" : \
                           dpp->frame_type == PKEX_SUB_COM_REV_RESP ? "reveal resp" : "no idea");
                    if (process_pkex_frame(&buf[1], framesize - 1, conv->handle) < 0) {
                        fprintf(stderr, "error processing PKEX frame");
                    }
                    break;
                case DPP_CONFIG_RESULT:
                    printf("DPP config result message...\n");
                    if (process_dpp_config_frame(BAD_DPP_SPEC_MESSAGE, &buf[1], framesize - 1, conv->handle) < 0) {
                        fprintf(stderr, "error processing DPP Config frame\n");
                    }
                    /*
                     * all done!
                     */
                    (void)srv_add_timeout(srvctx, SRV_MSEC(10), delete_conversation, conv);
//                    srv_rem_input(srvctx, fd);
//                    close(fd);
//                    TAILQ_REMOVE(&conversations, conv, entry);
//                    free(conv);
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
            if (process_dpp_config_frame(buf[0], &buf[1], framesize - 1, conv->handle) < 0) {
                fprintf(stderr, "error processing DPP Config frame\n");
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
cons_action_frame (unsigned char field, dpp_handle handle,
                   char *data, int len)
{
    char buf[8192], *ptr;
    uint32_t netlen;
    struct conversation *conv = NULL;

    TAILQ_FOREACH(conv, &conversations, entry) {
        if (handle == conv->handle) {
            break;
        }
    }
    if (conv == NULL) {
        fprintf(stderr, "can't find dpp instance!\n");
        return -1;
    }
    memset(buf, 0, sizeof(buf));
    ptr = buf;

    netlen = htonl(len + 1);
    memcpy(ptr, (char *)&netlen, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    
    *ptr = field;
    ptr++;
    
    memcpy(ptr, data, len < sizeof(buf) ? len : sizeof(buf));

    printf("sending %d byte message to relay\n", len + 1);
    if (write(conv->fd, buf, len + sizeof(uint32_t) + 1) < 1) {
        fprintf(stderr, "can't send message to relay!\n");
        return -1;
    }
    return len;
}

int
transmit_config_frame (dpp_handle handle, unsigned char field, char *data, int len)
{
    return cons_action_frame(field, handle, data, len);
}

int
transmit_auth_frame (dpp_handle handle, char *data, int len)
{
    return cons_action_frame(PUB_ACTION_VENDOR, handle, data, len);
}

int
transmit_discovery_frame (unsigned char tid, char *data, int len)
{
    return cons_action_frame(PUB_ACTION_VENDOR, (dpp_handle)tid, data, len);
}

int
transmit_pkex_frame (pkex_handle handle, char *data, int len)
{
    return cons_action_frame(PUB_ACTION_VENDOR, (dpp_handle)handle, data, len);
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

int
save_bootstrap_key (pkex_handle handle, void *param)
{
    FILE *fp = NULL;
    BIO *bio = NULL;
    char newone[1024], existing[1024], b64bskey[1024];
    unsigned char *ptr, mac[2*ETH_ALEN];
    int ret = -1, oc, ch, len, octets;
    EC_KEY *peerbskey = (EC_KEY *)param;
    struct conversation *conv;
    
    TAILQ_FOREACH(conv, &conversations, entry) {
        if (handle == conv->handle) {
            break;
        }
    }
    if (conv == NULL) {
        fprintf(stderr, "can't find dpp instance!\n");
        return -1;
    }

    /*
     * get the base64 encoded EC_KEY as onerow[1]
     */
    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
        fprintf(stderr, "unable to create bio!\n");
        goto fin;
    }
    (void)i2d_EC_PUBKEY_bio(bio, peerbskey);
    (void)BIO_flush(bio);
    len = BIO_get_mem_data(bio, &ptr);
    octets = EVP_EncodeBlock((unsigned char *)newone, ptr, len);
    BIO_free(bio);

    memset(b64bskey, 0, 1024);
    strncpy(b64bskey, newone, octets);

    if ((fp = fopen(bootstrapfile, "r+")) == NULL) {
        fprintf(stderr, "SSS: unable to open %s as bootstrapping file\n", bootstrapfile);
        goto fin;
    }
    ret = 0;
    printf("peer's bootstrapping key (b64 encoded)\n%s\n", b64bskey);
    while (!feof(fp)) {
        memset(existing, 0, 1024);
        if (fscanf(fp, "%d %d %d %s %s", &ret, &oc, &ch, mac, existing) < 1) {
            break;
        }
        if (strcmp((char *)existing, (char *)b64bskey) == 0) {
            fprintf(stderr, "SSS: bootstrapping key is trusted already\n");
//            goto fin;
        }
    }
    ret++;
    /*
     * bootstrapping file is index opclass channel macaddr key
     * but the controller doesn't care about opclass and channel 
     * and doesn't know anything about MAC addresses....
     */
    fprintf(fp, "%d 0 0 ffffffffffff %s\n", ret, b64bskey);

  fin:
    if (fp != NULL) {
        fclose(fp);
    }
    return ret;
}

void
new_connection (int fd, void *data)
{
    struct sockaddr_in *serv = (struct sockaddr_in *)data;
    struct conversation *conv = NULL;
    int sd, rlen, framesize, ret, opclass, channel, asn1len, found = 0;
    uint32_t netlen;
    unsigned int clen, mdlen = SHA256_DIGEST_LENGTH;
    char pkey[200];
    unsigned char buf[3000], mac[20], keyasn1[1024], keyhash[SHA256_DIGEST_LENGTH];
    dpp_action_frame *frame;
    EVP_MD_CTX *mdctx = NULL;
    TLV *rhash;
    FILE *fp;
    
    printf("new connection!!!\n");
    clen = sizeof(struct sockaddr_in);
    if ((sd = accept(fd, (struct sockaddr *)serv, &clen)) < 0) {
        fprintf(stderr, "failed to accept new relay connection!\n");
        return;
    }
    
    if (read(sd, (char *)&netlen, sizeof(uint32_t)) < 0) {
        fprintf(stderr, "unable to read message from relay!\n");
        goto fail;
    }
    netlen = ntohl(netlen);
    if (netlen > sizeof(buf)) {
        fprintf(stderr, "overflow attack by relay/client! Not gonna read in %d bytes\n",
                netlen);
        goto fail;
    }

    framesize = 0;
    while (netlen) {
        if ((rlen = read(sd, (buf + framesize), netlen)) < 1) {
            fprintf(stderr, "unable to read message from relay!\n");
            goto fail;
        }
        framesize += rlen;
        netlen -= rlen;
    }
    
    if (buf[0] != PUB_ACTION_VENDOR) {
        fprintf(stderr, "first message from relay not DPP/PKEX!\n");
        goto fail;
    }

    if ((conv = (struct conversation *)malloc(sizeof(struct conversation))) == NULL) {
        fprintf(stderr, "unable to create new connectin from relay!\n");
        goto fail;
    }
    memset(conv, 0, sizeof(struct conversation));
    conv->fd = sd;
    srv_add_input(srvctx, conv->fd, conv, message_from_relay);
    TAILQ_INSERT_HEAD(&conversations, conv, entry);

    frame = (dpp_action_frame *)&buf[1];
    switch (frame->frame_type) {
        case PKEX_SUB_EXCH_REQ:   // controller only does PKEXv2
            if ((conv->handle = pkex_create_peer(2)) < 1) {
                fprintf(stderr, "can't create pkex instance!\n");
                goto fail;
            }
            if (process_pkex_frame(&buf[1], framesize - 1, conv->handle) < 0) {
                fprintf(stderr, "error processing PKEX frame from relay!\n");
                goto fail;
            }
            break;
        case DPP_SUB_AUTH_REQUEST:
            printf("DPP auth request...\n");

            if ((conv->handle = dpp_create_peer(NULL, 0, 0, 0)) < 1) {
                goto fail;
            }
            if (process_dpp_auth_frame(&buf[1], framesize - 1, conv->handle) < 0) {
                fprintf(stderr, "error processing DPP auth frame from relay!\n");
                goto fail;
            }
            break;
        case DPP_CHIRP:
            /*
             * see if we know about this guy...
             */
            printf("DPP chirp!\n");
            if ((rhash = find_tlv(RESPONDER_BOOT_HASH, frame->attributes, framesize - 1)) == NULL) {
                goto fail;
            }
            if ((fp = fopen(bootstrapfile, "r")) == NULL) {
                goto fail;
            }
            if ((mdctx = EVP_MD_CTX_new()) == NULL) {
                goto fail;
            }
            while (!feof(fp)) {
                memset(pkey, 0, sizeof(pkey));
                if (fscanf(fp, "%d %d %d %s %s", &ret, &opclass, &channel, mac, pkey) < 0) {
                    continue;
                }
                if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)pkey, strlen(pkey))) < 0) {
                    continue;
                }
                print_buffer("asn1", keyasn1, asn1len);
                printf("checking %d...", ret);
                EVP_DigestInit(mdctx, EVP_sha256());
                EVP_DigestUpdate(mdctx, "chirp", strlen("chirp"));
                EVP_DigestUpdate(mdctx, keyasn1, asn1len - 1);
                EVP_DigestFinal(mdctx, keyhash, &mdlen);
                print_buffer("computed", keyhash, mdlen);
                print_buffer("chirped", TLV_value(rhash), SHA256_DIGEST_LENGTH); 
                if (memcmp(keyhash, TLV_value(rhash), SHA256_DIGEST_LENGTH) == 0) {
                    printf("YES!!!\n");
                    /* 
                     * if so, initiator and try mutual (responder decides anyway)
                     */
                    if ((conv->handle = dpp_create_peer((unsigned char *)&pkey[0], 1, 1, 0)) < 1) {
                        fclose(fp);
                        goto fail;
                    }
                    found = 1;
                    break;
                } else {
                    printf("no\n");
                }
            }
            fclose(fp);
            if (!found) {
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
        if (conv != NULL) {
            TAILQ_REMOVE(&conversations, conv, entry);
            free(conv);
        }
    }
    return;
}

int
change_dpp_freq (dpp_handle handle, unsigned long blah)
{
    return 1;
}

int change_dpp_channel (dpp_handle handle, unsigned char foo, unsigned char bar)
{
    return 1;
}

/*
 * we have a trusted key in the bootstrapping key file, go do DPP!
 */
int
bootstrap_peer (pkex_handle handle, int keyidx, int is_initiator, int mauth)
{
    FILE *fp;
    struct conversation *conv = NULL;
    int n, opclass, channel;
    unsigned char peermac[ETH_ALEN]; 
    unsigned char keyb64[1024];
    char mac[20], *ptr;

    printf("looking for bootstrap key index %d\n", keyidx);
    if ((fp = fopen(bootstrapfile, "r")) == NULL) {
        return -1;
    }
    while (!feof(fp)) {
        memset(keyb64, 0, sizeof(keyb64));
        if (fscanf(fp, "%d %d %d %s %s", &n, &opclass, &channel, mac, keyb64) < 1) {
            fprintf(stderr, "unable to read from bootstrap key file\n");
            fclose(fp);
            return -1;
        }
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

    TAILQ_FOREACH(conv, &conversations, entry) {
        if (conv->handle == (dpp_handle)handle) {
            break;
        }
    }
    if (conv == NULL) {
        fprintf(stderr, "unable to find bootstrapping handle %x\n", handle);
        return -1;
    } else if (conv->handle) {
        pkex_destroy_peer(conv->handle);
    }
    /*
     * reuse the conversation structure, just delete the pkex state
     * and migrate local state over to dpp state
     */
    if ((conv->handle = dpp_create_peer(keyb64, is_initiator, mauth, 0)) < 1) {
        close(conv->fd);
        free(conv);
        return -1;
    }
    return 1;
}

void
badconn (int fd, void *data)
{
    srv_rem_input(srvctx, fd);
    close(fd);
}

void
term (unsigned short reason)
{
    /*
     * not used by controller
     */
    return;
}

int
main (int argc, char **argv)
{
    int c, debug = 0, is_initiator = 0, config_or_enroll = 0, mutual = 1, do_pkex = 0, do_dpp = 1;
    int opt, infd;
    struct sockaddr_in serv;
    char relay[20], password[80], keyfile[80], signkeyfile[80], enrollee_role[10], mudurl[80];
    char *ptr, *endptr, identifier[80], pkexinfo[80], caip[40];
    unsigned char targetmac[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    if ((srvctx = srv_create_context()) == NULL) {
        fprintf(stderr, "%s: cannot create service context!\n", argv[0]);
        exit(1);
    }
    TAILQ_INIT(&conversations);
    memset(bootstrapfile, 0, 80);
    memset(signkeyfile, 0, 80);
    memset(mudurl, 0, 80);
    memset(identifier, 0, 80);
    memset(pkexinfo, 0, 80);
    memset(caip, 0, 40);
    for (;;) {
        c = getopt(argc, argv, "hirm:k:I:B:x:bae:c:d:p:n:z:w:");
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
            case 'w':
                strcpy(caip, optarg);
                break;
            case 'x':
                keyidx = atoi(optarg);
                break;
            case 'z':
                strcpy(pkexinfo, optarg);
                break;
            case 'u':
                strcpy(mudurl, optarg);
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
                        "\t-u <url> to find a MUD file (enrollee only)\n"
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
    serv.sin_port = htons(DPP_PORT);
    if ((bind(infd, (struct sockaddr *)&serv, sizeof(struct sockaddr_in)) < 0) ||
        (listen(infd, 0) < 0)) {
        fprintf(stderr, "%s: unable to bind/listen TCP socket!\n", argv[0]);
        exit(1);
    }
    srv_add_input(srvctx, infd, &serv, new_connection);
    srv_add_exceptor(srvctx, badconn);

    /*
     * initialize data structures...
     */
    if (do_pkex) {
        if (pkex_initialize(is_initiator, password, 
                            identifier[0] == 0 ? NULL : identifier,
                            pkexinfo[0] == 0 ? NULL : pkexinfo, keyfile, debug) < 0) {
            fprintf(stderr, "%s: cannot configure PKEX/DPP, check config file!\n", argv[0]);
            exit(1);
        }
    }
    if (do_dpp) {
        if (dpp_initialize(config_or_enroll, keyfile,
                           signkeyfile[0] == 0 ? NULL : signkeyfile, enrollee_role,
                           mudurl[0] == 0 ? NULL : mudurl, 0, caip[0] == 0 ? "127.0.0.1" : caip,
                           0, 0, debug) < 0) {
            fprintf(stderr, "%s: cannot configure DPP, check config file!\n", argv[0]);
            exit(1);
        }
    }
    /*
     * TODO: handle initiation, need a MAC address of the target plumbed from CLI,
     * bootstrap the peer with the indicated idx getting a handle, then create new
     * controller-to-relay message to create state for the relay to bind to that MAC
     * address, then begin the conversation using that handle.
     */
    if (is_initiator) {
//        bootstrap_peer(relay, keyidx, is_initiator, mutual);
        fprintf(stderr, "don't support relay initiation yet\n");
        exit(1);
    }

    srv_main_loop(srvctx);

    exit(1);
}
