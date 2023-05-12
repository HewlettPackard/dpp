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
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "service.h"
#include "talk2ca.h"

extern service_context srvctx;

/*
 * Routines to talk to CA
 *
 * The CA is a very simple openssl app that reads in a PKCS10, signs it and
 * sends back a PKCS7. It communicates over a TCP port and it passed a
 * uint32 that doubles as a message indicator and a length of message being
 * sent.
 *
 * Sending the PKCS10 and receiving the PKCS7 are asynchronous. The CA could
 * respond immediately or it can take its time. So sending the PKCS10 involves
 * passing a callback and data. The callback is passed an opaque int (actually
 * a socket) and the data when the PKCS7 is ready. The callback is expected
 * to obtain the PKCS7 by passing the opaque int back.
 *
 * This backend stuff to talk to the CA is easily replacable by whatever interface
 * you use to talk to your CA but if you leave the APIs that DPP uses alone then
 * it's all invisible to DPP.
 */

static int
reads (int sock, char *data, int len)
{
    int rlen, sofar, left;

    sofar = 0;
    left = len;
    while (left) {
        if ((rlen = read(sock, (data + sofar), left)) < 1) {
            fprintf(stderr, "reads: returned %d after reading %d with %d left\n",
                    rlen, sofar, left);
            return sofar;
        }
        sofar += rlen;
        left -= rlen;
    }
    return sofar;
}

static int
writes (int sock, char *data, int len)
{
    int wlen, sofar, left;

    sofar = 0;
    left = len;
    while (left) {
        if ((wlen = write(sock, (data + sofar), left)) < 1) {
            fprintf(stderr, "writes: returned %d after writing %d with %d left\n",
                      wlen, sofar, left);
            return sofar;
        }
        sofar += wlen;
        left -= wlen;
    }
    return sofar;
}

/*
 * get a PKCS7 of certs in the event that the trust chain for the client
 * cert that is sent back as a PKCS7 differs from the trust chain for the
 * server that it will be speaking to with its certificate.
 *
 * Weird, I know, but people wanted to support this.
 *
 * Returns 0 in the event that the CA trust root will be sent back as part of
 * the client's PKCS7-- basically, "don't worry about separate CA certs" is the
 * message back to DPP.
 */
int
get_cacerts (char **cap7, char *caip)
{
    int s, len;
    struct sockaddr_in sin;
    uint32_t msgsinglet;

    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "unable to open socket to CA!\n");
        return -1;
    }
    memset((char *)&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(caip);
    sin.sin_port = htons(CAPORT);
    if (connect(s, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) < 0) {
        fprintf(stderr, "unable to connect to CA!\n");
        return -1;
    }
    msgsinglet = 0;
    if (writes(s, (char *)&msgsinglet, sizeof(uint32_t)) < sizeof(uint32_t)) {
        fprintf(stderr, "cannot request CA P7!\n");
        close(s);
        return -1;
    }
    if (reads(s, (char *)&msgsinglet, sizeof(uint32_t)) < 0) {
        fprintf(stderr, "cannot determine size of CA P7!\n");
        close(s);
        return -1;
    }
    msgsinglet = htonl(msgsinglet);
    len = (msgsinglet & 0xffff);
    printf("signlet is %d, len is %d\n", msgsinglet, len);
    if (len) {
        if ((*cap7 = malloc(len+1)) == NULL) {
            fprintf(stderr, "cannot allocate space for CA P7!\n");
            close(s);
            return -1;
        }
        memset(*cap7, 0, len+1);
        if (reads(s, *cap7, len) < len) {
            fprintf(stderr, "cannot read %d byte CA P7!\n", len);
            free(*cap7);
            close(s);
            return -1;
        }
    } 
    close(s);
    return len;
}

/*
 * sends a PKCS10 to the CA
 *
 * gets passed p10, length of p10, IP address of CA, some data to pass
 * to a callback when the PKCS7 is ready, and the callback to call.
 *
 * returns the socket (which should be treated as an opaque indicator of
 * success or failure), we'll get it back when the callback is called.
 */
int
send_pkcs10 (char *p10, int p10len, char *caip, void *data, fdcb cb)
{
    struct sockaddr_in sin;
    uint32_t msgsinglet;
    unsigned char *msg, *ptr;
    int s;

    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "cannot create socket to talk to CA!\n");
        return -1;
    }
    
    if ((msg = malloc(p10len + sizeof(uint32_t))) == NULL) {
        fprintf(stderr, "cannot allocate space to make p10 request!\n");
        return -1;
    }
    ptr = msg;

    memset((char *)&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(caip);
    sin.sin_port = htons(CAPORT);
    if (connect(s, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) < 0) {
        fprintf(stderr, "cannot connect to CA to make p10 request!\n");
        close(s);
        free(msg);
        return -1;
    }
    
    msgsinglet = (1 << 16) | (p10len & 0xffff);
    msgsinglet = htonl(msgsinglet);
    memcpy(ptr, (char *)&msgsinglet, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    memcpy(ptr, p10, p10len);
    if (send(s, (char *)msg, p10len+sizeof(uint32_t), 0) < (p10len+sizeof(uint32_t))) {
        fprintf(stderr, "cannot send p10 to CA!\n");
        close(s);
        free(msg);
        return -1;
    }
    free(msg);
    srv_add_input(srvctx, s, data, cb);
    return s;
}

/*
 * gets a PKCS7 from CA
 *
 * passed the socket that was invoked with the callback and a pointer to the p7
 *
 * since the socket is treated as opaque by the caller, we close it here
 */
int
get_pkcs7 (int s, char **p7)
{
    uint32_t msgsinglet;
    int len;

    if (reads(s, (char *)&msgsinglet, sizeof(uint32_t)) < 0) {
        fprintf(stderr, "cannot read message header from CA!\n");
        close(s);
        return 0;
    }
    msgsinglet = htonl(msgsinglet);
    len = (msgsinglet & 0xffff);
    if ((*p7 = malloc(len+1)) == NULL) {
        fprintf(stderr, "cannot alloc space for p7!\n");
        close(s);
        return 0;
    }
    memset(*p7, 0, len+1);
    if (reads(s, (char *)*p7, len) < len) {
        fprintf(stderr, "cannot read p7!\n");
        close(s);
        return 0;
    }
    srv_rem_input(srvctx, s);
    close(s);
    return len;
}
