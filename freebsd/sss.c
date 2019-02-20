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
#include <signal.h>
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
#include "dpp.h"
#include "pkex.h"
#include "radio.h"

struct interface {
    TAILQ_ENTRY(interface) entry;
    unsigned char ifname[IFNAMSIZ];
    unsigned char bssid[ETH_ALEN];
    unsigned char is_loopback;
    int fd;     /* BPF socket */
};
TAILQ_HEAD(bar, interface) interfaces;

struct dpp_instance {
    TAILQ_ENTRY(dpp_instance) entry;
    dpp_handle handle;
    unsigned char tid;
    unsigned char mymac[ETH_ALEN];
    unsigned char peermac[ETH_ALEN];
};
TAILQ_HEAD(foo, dpp_instance) dpp_instances;

service_context srvctx;
static int discovered = -1;
unsigned char our_ssid[33];
char bootstrapfile[80];

static void
dump_ssid (struct ieee80211_mgmt_frame *frame, int len)
{
    char el_id, el_len, ssid[33];
    unsigned char *ptr;
    int left;

    ptr = frame->beacon.variable;
    left = len - (IEEE802_11_HDR_LEN + sizeof(frame->beacon));
    while (left > 2) {
        el_id = *ptr++;
        left--;
        el_len = *ptr++;
        left--;
        if (el_len > left) {
            return;
        }
        if (el_id == IEEE802_11_IE_SSID) {
            if (el_len > 32) {
                return;
            }
            memset(ssid, 0, sizeof(ssid));
            memcpy(ssid, ptr, el_len);
            break;
        }
    }
}

struct dpp_instance *
find_instance_by_mac (unsigned char *me, unsigned char *peer)
{
    struct dpp_instance *found;
    unsigned char broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    
    TAILQ_FOREACH(found, &dpp_instances, entry) {
        if (memcmp(found->mymac, me, ETH_ALEN) == 0) {
            if (memcmp(found->peermac, peer, ETH_ALEN) == 0) {
                break;
            }
            if (memcmp(found->peermac, broadcast, ETH_ALEN) == 0) {
                memcpy(found->peermac, peer, ETH_ALEN);
                break;
            }
        }
    }
    if (found == NULL) {
        fprintf(stderr, "unable to find dpp peer, src="MACSTR", dst="MACSTR"\n",
                MAC2STR(me), MAC2STR(peer));
    }
    return found;
}

struct dpp_instance *
find_instance_by_handle (dpp_handle handle)
{
    struct dpp_instance *found;
    
    TAILQ_FOREACH(found, &dpp_instances, entry) {
        if (found->handle == handle) {
            break;
        }
    }
    if (found == NULL) {
        fprintf(stderr, "unable to find dpp peer, handle = %d\n", handle);
    }
    return found;
}

struct dpp_instance *
find_instance_by_tid (unsigned char tid)
{
    struct dpp_instance *found;
    
    TAILQ_FOREACH(found, &dpp_instances, entry) {
        if (found->tid == tid) {
            break;
        }
    }
    if (found == NULL) {
        fprintf(stderr, "unable to find dpp peer, tid = %d\n", tid);
    }
    return found;
}

struct dpp_instance *
create_dpp_instance (unsigned char *mymac, unsigned char *peermac, unsigned char *bskey)
{
    struct dpp_instance *instance;
    
    if ((instance = (struct dpp_instance *)malloc(sizeof(struct dpp_instance))) == NULL) {
        return NULL;
    }
    memcpy(instance->mymac, mymac, ETH_ALEN);
    memcpy(instance->peermac, peermac, ETH_ALEN);
    if ((instance->handle = dpp_create_peer(bskey)) < 1) {
        free(instance);
        return NULL;
    }
    TAILQ_INSERT_HEAD(&dpp_instances, instance, entry);
    
    return instance;
}

struct dpp_instance *
create_discovery_instance (unsigned char *mymac, unsigned char *peermac)
{
    struct dpp_instance *instance;
    
    if ((instance = (struct dpp_instance *)malloc(sizeof(struct dpp_instance))) == NULL) {
        return NULL;
    }
    memcpy(instance->mymac, mymac, ETH_ALEN);
    memcpy(instance->peermac, peermac, ETH_ALEN);
    instance->tid = get_dpp_discovery_tid();
    TAILQ_INSERT_HEAD(&dpp_instances, instance, entry);
    
    return instance;
}

static void
bpf_in (int fd, void *data)
{
    struct interface *inf = (struct interface *)data;
    dpp_action_frame *dpp;
    struct dpp_instance *instance;
    char el_id, el_len, ssid[33];
    unsigned char buf[2048], *ptr, *els, pmk[PMK_LEN], pmkid[PMKID_LEN];
    struct bpf_hdr *hdr;
    struct ieee80211_mgmt_frame *frame;
    unsigned short frame_control;
    int type, stype, len, framesize, left;
    unsigned char broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

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
         * even though we explicitly state that we don't want to see our
         * own frames the "multicast" "beacons" we send over loopback
         * seem to get delivered to us anyway. Drop them.
         */
        if (memcmp(frame->sa, inf->bssid, ETH_ALEN) == 0) {
            /*
             * there might be another frame...
             */
            len -= BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
            ptr += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
            continue;
        }
        /*
         * if it's not for us and not broadcast, ignore it
         */
        if (memcmp(frame->da, inf->bssid, ETH_ALEN) &&
            memcmp(frame->da, broadcast, ETH_ALEN)) {
            return;
        }

        frame_control = ieee_order(frame->frame_control);
        type = IEEE802_11_FC_GET_TYPE(frame_control);
        stype = IEEE802_11_FC_GET_STYPE(frame_control);

        if (type == IEEE802_11_FC_TYPE_MGMT) {
            switch (stype) {
                case IEEE802_11_FC_STYPE_ACTION:
                    /*
                     * if it's not a public action frame then we don't care about it!
                     */
                    if (frame->action.category != ACTION_PUBLIC) {
                        return;
                    }
                    left = framesize - (IEEE802_11_HDR_LEN + sizeof(frame->action));
                /*
                 * it's very unfortunate that 3 protocols use public action frames which
                 * require looking into the contents to demultiplex while 1 protocol uses
                 * gas frames whose field is used for demultiplexing...
                 */
                    switch (frame->action.field) {
                        case PUB_ACTION_VENDOR:
                            /* 
                             * DPP Auth, Discovery, and PKEX
                             */
                            dpp = (dpp_action_frame *)frame->action.variable;
                            switch (dpp->frame_type) {
                                /*
                                 * DPP Auth
                                 */
                                case DPP_SUB_AUTH_REQUEST:
                                case DPP_SUB_AUTH_RESPONSE:
                                case DPP_SUB_AUTH_CONFIRM:
                                    if ((instance = find_instance_by_mac(inf->bssid, frame->sa)) == NULL) {
                                        fprintf(stderr, "no dpp instance at " MACSTR " from " MACSTR "\n",
                                                MAC2STR(inf->bssid), MAC2STR(frame->sa));
                                        return;
                                    }
                                    if (process_dpp_auth_frame(frame->action.variable, left, instance->handle) < 0) {
                                        fprintf(stderr, "error processing DPP frame from " MACSTR "\n",
                                                MAC2STR(frame->sa));
                                    }
                                    break;
                                /*
                                 * DPP Discovery
                                 */
                                case DPP_SUB_PEER_DISCOVER_REQ:
                                    if ((instance = create_discovery_instance(inf->bssid, frame->sa)) == NULL) {
                                        break;
                                    }
                                    if (process_dpp_discovery_frame(frame->action.variable, left, instance->tid,
                                                                    pmk, pmkid) < 0) {
                                        fprintf(stderr, "error processing DPP Discovery frame from " MACSTR "\n",
                                                MAC2STR(frame->sa));
                                    }
                                    break;
                                case DPP_SUB_PEER_DISCOVER_RESP:
                                    if ((instance = find_instance_by_mac(inf->bssid, frame->sa)) == NULL) {
                                        fprintf(stderr, "no dpp instance at " MACSTR " from " MACSTR "\n",
                                                MAC2STR(inf->bssid), MAC2STR(frame->sa));
                                        return;
                                    }
                                    if (process_dpp_discovery_frame(frame->action.variable, left, instance->tid, 
                                                                    pmk, pmkid) < 0) {
                                        fprintf(stderr, "error processing DPP Discovery frame from " MACSTR "\n",
                                                MAC2STR(frame->sa));
                                    }
                                    break;
                                /*
                                 * PKEX
                                 */
                                case PKEX_SUB_EXCH_REQ:
                                case PKEX_SUB_EXCH_RESP:
                                case PKEX_SUB_COM_REV_REQ:
                                case PKEX_SUB_COM_REV_RESP:
                                    if (process_pkex_frame(frame->action.variable, left, inf->bssid, frame->sa) < 0) {
                                        fprintf(stderr, "error processing PKEX frame from " MACSTR "\n",
                                                MAC2STR(frame->sa));
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
                             * DPP Configuration Protocol
                             */
                            if ((instance = find_instance_by_mac(inf->bssid, frame->sa)) == NULL) {
                                fprintf(stderr, "no dpp instance at " MACSTR " from " MACSTR "\n",
                                        MAC2STR(inf->bssid), MAC2STR(frame->sa));
                                return;
                            }
                            if (process_dpp_config_frame(frame->action.field, frame->action.variable, left,
                                                         instance->handle) < 0) {
                                fprintf(stderr, "error processing DPP Config frame from " MACSTR "\n",
                                        MAC2STR(frame->sa));
                            }
                            break;
                        default:
                            fprintf(stderr, "weird action field (%x)\n", frame->action.field);
                            break;
                    }
                    break;
                case IEEE802_11_FC_STYPE_BEACON:
                    if (discovered != 0) {
                        /*
                         * not yet provisioned or already discovered
                         */
                        return;
                    }
                    dump_ssid(frame, framesize);
                    els = frame->beacon.variable;
                    left = framesize - (IEEE802_11_HDR_LEN + sizeof(frame->beacon));
                    /*
                     * els is the next IE in the beacon,
                     * left is how much is left to read in the beacon
                     */
                    while (left > 2) {
                        el_id = *els++; 
                        left--;
                        el_len = *els++; 
                        left--;
                        if (el_len > left) {
                            /*
                             * someone's trying to mess with us...
                             */
                            break;
                        }
                        if (el_id == IEEE802_11_IE_SSID) { 
                            if (el_len > 32) {
                                /*
                                 * again with the messing...
                                 */
                                break;
                            }
                            memset(ssid, 0, sizeof(ssid));
                            memcpy(ssid, els, el_len);
                            /*
                             * if it's not an interesting ssid then ignore the beacon
                             * otherwise if it's our's, discover the AP
                             */
                            if ((el_len == 0) || memcmp(ssid, our_ssid, el_len)) {
                                break;
                            }
                            if ((instance = create_discovery_instance(inf->bssid, frame->sa)) == NULL) {
                                break;
                            }
                            if (dpp_begin_discovery(instance->tid) > 0) {
                                discovered = 1;
                            }
                            break;
                        }
                        els += el_len;
                        left -= el_len;
                    }
                    break;
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
        fprintf(stderr, "can't find " MACSTR " to send mgmt frame!\n",
                MAC2STR(frame->sa));
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
    printf("sending acton frame from " MACSTR " to " MACSTR "\n", 
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

/*
 * wrappers to send PKEX and DPP action frames
 */
int
transmit_config_frame (dpp_handle handle, unsigned char field, char *data, int len)
{
    struct dpp_instance *instance;

    if ((instance = find_instance_by_handle(handle)) == NULL) {
        fprintf(stderr, "can't find state by handle %d\n", handle);
        return -1;
    }
    return cons_action_frame(field, instance->mymac, instance->peermac, data, len);
}

int
transmit_auth_frame (dpp_handle handle, char *data, int len)
{
    struct dpp_instance *instance;

    if ((instance = find_instance_by_handle(handle)) == NULL) {
        fprintf(stderr, "can't find state by handle %d\n", handle);
        return -1;
    }
    return cons_action_frame(PUB_ACTION_VENDOR, instance->mymac, instance->peermac, data, len);
}

int
transmit_discovery_frame (unsigned char tid, char *data, int len)
{
    struct dpp_instance *instance;

    if ((instance = find_instance_by_tid(tid)) == NULL) {
        fprintf(stderr, "can't find state by tid %d\n", tid);
        return -1;
    }
    return cons_action_frame(PUB_ACTION_VENDOR, instance->mymac, instance->peermac, data, len);
}

int
transmit_pkex_frame (unsigned char *mymac, unsigned char *peermac, char *data, int len)
{
    return cons_action_frame(PUB_ACTION_VENDOR, mymac, peermac, data, len);
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

/*
 * send_beacon()
 *      beacons are normally sent out automagically by the radio but if we're
 *      simulating this protocol over the loopback we need to send them here.
 */
static void
send_beacon (timerid tid, void *data)
{
    struct interface *inf = (struct interface *)data;
    struct ieee80211_mgmt_frame *frame;
    unsigned char buf[2048], *el;
    unsigned char broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    int len, blen;
    unsigned long af;

    if (inf == NULL) {
        return;
    }
    memset(buf, 0, sizeof(buf));
    /*
     * add the loopback pseudo-header to indicate or pseudo-AF
     */
    af = AF_INET;
    memcpy(buf, &af, sizeof(unsigned long));
    frame = (struct ieee80211_mgmt_frame *)(buf + sizeof(unsigned long));
    frame->frame_control = ieee_order((IEEE802_11_FC_TYPE_MGMT << 2 | IEEE802_11_FC_STYPE_BEACON << 4));
    memcpy(frame->da, broadcast, ETH_ALEN);
    memcpy(frame->sa, inf->bssid, ETH_ALEN);
    memcpy(frame->bssid, inf->bssid, ETH_ALEN);

    /*
     * not a truely valid beacon but so what, this is a simulator and
     * all we really care about is the ssid
     */
    el = frame->beacon.variable;
    *el = IEEE802_11_IE_SSID;
    el++;
    *el = strlen(our_ssid);
    el++;
    memcpy(el, our_ssid, strlen(our_ssid));
    el += strlen(our_ssid);

    len = el - buf;
    blen = write(inf->fd, buf, len);
    if (blen < 0) {
        perror("write");
    }
    srv_add_timeout(srvctx, SRV_MSEC(100), send_beacon, inf);
    return;
}

int
provision_connector (char *role, unsigned char *ssid, int ssidlen,
                     unsigned char *connector, int connlen, dpp_handle handle)
{
    struct interface *inf = NULL;
    struct dpp_instance *instance;
    struct ieee80211req ireq;
    struct ifmediareq ifmreq;
    int s;
    
    if ((instance = find_instance_by_handle(handle)) == NULL) {
        fprintf(stderr, "no DPP instance to provision a connector for!\n");
        return -1;
    }
    
    printf("connector:\n%.*s\nwith ", connlen, connector);
    if (ssidlen == 1 && ssid[0] == '*') {
        printf("any SSID\n");
    } else {
        printf("SSID %.*s\n", ssidlen, ssid);
    }
    if ((s = socket(PF_INET, SOCK_RAW, 0)) < 0) {
        fprintf(stderr, "unable to get raw socket to determine interface flags!\n");
        return -1;
    }

    memcpy(our_ssid, ssid, ssidlen);
    if (strncmp(role, "ap", 2) == 0) {
        TAILQ_FOREACH(inf, &interfaces, entry) {
            if (memcmp(instance->mymac, inf->bssid, ETH_ALEN) == 0) {
                break;
            }
        }
        if (inf == NULL) {
            fprintf(stderr, "can't find " MACSTR " to send mgmt frame!\n",
                    MAC2STR(instance->mymac));
            return -1;
        }
        if (inf->is_loopback) {
            srv_add_timeout(srvctx, SRV_MSEC(1), send_beacon, inf);
        } else {
            /*
             * set the ssid
             */
            memset(&ireq, 0, sizeof(struct ieee80211req));
            strlcpy(ireq.i_name, inf->ifname, IFNAMSIZ);
            ireq.i_type = IEEE80211_IOC_SSID;
            ireq.i_data = our_ssid;
            ireq.i_len = strlen(our_ssid);

            if (ioctl(s, SIOCS80211, &ireq) < 0) {
                fprintf(stderr, "unable to set SSID!\n");
                perror("ioctl");
                return -1;
            }
            /*
             * make it an AP
             */
            memset(&ifmreq, 0, sizeof(ifmreq));
            strlcpy(ifmreq.ifm_name, inf->ifname, IFNAMSIZ);
            if (ioctl(s, SIOCGIFMEDIA, &ifmreq) < 0) {
                fprintf(stderr, "unable to get mediaopt!\n");
                return -1;
            }
            /*
             * first turn off anything that might've been, then turn on hostap
             */
            ifmreq.ifm_current &= ~(IFM_IEEE80211_MONITOR | IFM_IEEE80211_ADHOC | IFM_IEEE80211_IBSS);
            if (ioctl(s, SIOCSIFMEDIA, &ifmreq) < 0) {
                fprintf(stderr, "unable to set mediaopt!\n");
                perror("ioctl");
                return -1;
            }
            ifmreq.ifm_current |= IFM_IEEE80211_HOSTAP;
            if (ioctl(s, SIOCSIFMEDIA, &ifmreq) < 0) {
                fprintf(stderr, "unable to set mediaopt!\n");
                perror("ioctl");
                return -1;
            }
        }
        discovered = 1;
    } else if (strncmp(role, "sta", 3) == 0) {
        TAILQ_FOREACH(inf, &interfaces, entry) {
            if (memcmp(instance->mymac, inf->bssid, ETH_ALEN) == 0) {
                break;
            }
        }
        if (inf == NULL) {
            fprintf(stderr, "can't find " MACSTR " to send mgmt frame!\n",
                    MAC2STR(instance->mymac));
            return -1;
        }
        if (!inf->is_loopback) {
            /*
             * make it a STA (which is just not anything else)
             */
            memset(&ifmreq, 0, sizeof(ifmreq));
            strlcpy(ifmreq.ifm_name, inf->ifname, IFNAMSIZ);
            if (ioctl(s, SIOCGIFMEDIA, &ifmreq) < 0) {
                fprintf(stderr, "unable to get mediaopt!\n");
                return -1;
            }
            ifmreq.ifm_current &= ~(IFM_IEEE80211_HOSTAP | IFM_IEEE80211_MONITOR | IFM_IEEE80211_ADHOC | IFM_IEEE80211_IBSS);
            if (ioctl(s, SIOCSIFMEDIA, &ifmreq) < 0) {
                fprintf(stderr, "unable to set mediaopt!\n");
                perror("ioctl");
                return -1;
            }
        }
        discovered = 0;
    } else {
        fprintf(stderr, "don't know what kind of device we are to do discovery: %s!\n", role);
    }
    return 1;
}
    
static void
add_interface (unsigned char *ptr)
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
        RAND_pseudo_bytes(&inf->bssid[0], ETH_ALEN);
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

/*
 * chan2freq()
 *      convert an 802.11 channel into a frequencey, stolen from ifconfig...
 */
static unsigned int
chan2freq(unsigned int chan)
{
    /*
     * "Kenneth, what is the frequency!!!????"
     *          - William Tager
     */
    if (chan == 14)
        return 2484;
    if (chan < 14)			/* 0-13 */
        return 2407 + chan*5;
    if (chan < 27)			/* 15-26 */
        return 2512 + ((chan-15)*20);
    return 5000 + (chan*5);
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

int
change_dpp_channel (dpp_handle handle, unsigned char class, unsigned char channel)
{
    struct dpp_instance *instance;

    if ((instance = find_instance_by_handle(handle)) == NULL) {
        return -1;
    }
    return change_channel(instance->mymac, class, channel);
}

/*
 * takes one of our mac addresses and an index into the bootstrapping key file.
 * Initiates DPP to peer whose DPP URI is at "keyidx".
 */
int
bootstrap_peer (unsigned char *mymac, int keyidx)
{
    FILE *fp;
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
    if (change_channel(mymac, opclass, channel) < 0) {
        fprintf(stderr, "peer's channel and operating class is not supported!\n");
        return -1;
    }
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

    if (create_dpp_instance(mymac, peermac, keyb64) == NULL) {
        fprintf(stderr, "unable to create peer!\n");
    } else {
        printf("new peer is at " MACSTR "\n", MAC2STR(peermac));
    }
    
    return 1;
}

int
main (int argc, char **argv)
{
    int s, c, debug = 0, is_initiator = 0, config_or_enroll = 0, mutual = 1, do_pkex = 0, do_dpp = 1, keyidx = 0;
    unsigned char opclass = 81, channel = 6;
    int mediaopt, chchan = 0;
    struct interface *inf;
    struct ifreq ifr;
    struct ieee80211req ireq;
    struct ifmediareq ifmreq;
    char interface[10], password[80], keyfile[80], signkeyfile[80], enrollee_role[10];
    char *cruft, identifier[80], pkexinfo[80];
    unsigned char targetmac[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    char *ptr, *endptr;
    size_t needed;
    int mib[6];
    struct if_msghdr *ifm;
    struct sockaddr_dl *sdl;

    if ((srvctx = srv_create_context()) == NULL) {
        fprintf(stderr, "%s: cannot create service context!\n", argv[0]);
        exit(1);
    }
    TAILQ_INIT(&interfaces);
    TAILQ_INIT(&dpp_instances);

    strcpy(bootstrapfile, "none");
    strcpy(signkeyfile, "none");
    strcpy(identifier, "none");
    /*
     * default channel, operating class, and mode
     */
    channel = 6;
    opclass = 81;
    mediaopt = RADIO_ADHOC;

    for (;;) {
        c = getopt(argc, argv, "hirm:k:I:B:x:bae:c:d:p:n:z:f:g:s");
        if (c < 0) {
            break;
        }
        switch (c) {
            case 'I':           /* interface */
                strcpy(interface, optarg);
                printf("adding interface %s...\n", interface);
                add_interface(interface);
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
            case 'f':           /* channel */
                channel = atoi(optarg);
                break;
            case 'g':           /* operating class */
                opclass = atoi(optarg);
                break;
            case 's':
                chchan = 1;
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
                        "\t-I <interface> to add to DPP\n"
                        "\t-B <filename> of peer bootstrappign keys\n"
                        "\t-p <password> to use for PKEX\n"
                        "\t-f <channel> to use with DPP\n"
                        "\t-g <opclass> operating class to use with DPP\n"
                        "\t-z <info> to pass along with public key in PKEX\n"
                        "\t-n <identifier> for the code used in PKEX\n"
                        "\t-k <filename> my bootstrapping key\n"
                        "\t-b  bootstrapping (PKEX) only, don't run DPP\n"
                        "\t-x  <index> DPP only with key <index> in -B <filename>, don't do PKEX\n"
                        "\t-m <MAC address> to initiate to, otherwise uses broadcast\n"
                        "\t-s  change opclass/channel to what was set with -f and -g\n"
                        "\t-d <debug> set debugging mask\n",
                        argv[0]);
                exit(1);
                
        }
    }
    /*
     * if we're doing DPP w/mutual authentication and/or doing PKEX then
     * a bootstrapping key has to be included
     */
    if ((mutual || do_pkex) && strcmp(bootstrapfile, "none") == 0) {
        fprintf(stderr, "%s: specify a peer bootstrapping key file with -B <filename>\n", argv[0]);
        exit(1);
    }

    if (TAILQ_EMPTY(&interfaces)) {
        fprintf(stderr, "%s: no interfaces defined!\n", argv[0]);
        add_interface("lo");
    }
    /*
     * ...and configure the radio!
     */
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
            ireq.i_val = 2;
            if (ioctl(s, SIOCS80211, &ireq) < 0) {
                fprintf(stderr, "%s: unable to set RSN!\n", argv[0]);
                perror("ioctl setting RSN");
                exit(1);
            }
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
            if (chchan == 0) {
                /*
                 * set the indicated channel and band now if we're not supposed
                 * to do in mid-DPP exchange
                 */
                if (change_channel(inf->bssid, opclass, channel) < 0) {
                    fprintf(stderr, "%s: operating class/channel of %d/%d is not supported!\n",
                            argv[0], opclass, channel);
                    exit(1);
                }
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
    }
    if (is_initiator) {
        printf("initiating to " MACSTR "\n", MAC2STR(targetmac));
    }

    /*
     * initialize data structures...
     */
    if (do_pkex) {
        if (pkex_initialize(is_initiator, password, identifier, pkexinfo, keyfile, bootstrapfile,
                            opclass, channel, debug) < 0) {
            fprintf(stderr, "%s: cannot configure PKEX, check config file!\n", argv[0]);
            exit(1);
        }
    }
    if (do_dpp) {
        /*
         * we've already changed channels, if needed. If 
         */
        if (chchan == 0) {
            channel = 0;
            opclass = 0;
        }
        if (dpp_initialize(is_initiator, config_or_enroll, mutual, keyfile, 
                           signkeyfile, enrollee_role, opclass, channel, debug) < 0) {
            fprintf(stderr, "%s: cannot configure DPP, check config file!\n", argv[0]);
            exit(1);
        }
    }

    TAILQ_FOREACH(inf, &interfaces, entry) {
        /*
         * For each interface we're active on...
         *
         * if we're the initiator, then either create a peer from existing
         * bootstrapping info or do pkex.
         *
         * if we're the responder, then PKEX is already ready, just wait,
         * otherwise create a DPP peer and wait.
         */
        if (is_initiator) {
            if (!do_pkex) {
                bootstrap_peer(inf->bssid, keyidx);
            } else {
                pkex_initiate(inf->bssid, targetmac);
            }
        } else {
            if (!do_pkex) {
                create_dpp_instance(inf->bssid, targetmac, NULL);
            }
        }
    }
    srv_main_loop(srvctx);

    exit(1);
}
