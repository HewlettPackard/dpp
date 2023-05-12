/*
 * ecca - stand-alone CA serving up ECC certificates 
 *
 * Copyright (c) Dan Harkins, 2014-2020
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
 *
 *  This permission does not include a grant of any permissions, rights,
 *  or licenses by any employers or corporate entities affiliated with
 *  the copyright holder.
 *
 *  "DISCLAIMER OF LIABILITY
 *  
 *  THIS SOFTWARE IS PROVIDED BY DAN HARKINS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INDUSTRIAL LOUNGE BE LIABLE
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
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "service.h"

service_context srvctx;
int unique = 0, cainp7;

static int
reads (int sock, char *data, int len)
{
    int left, sofar, rlen;

    left = len;
    sofar = 0;
    while (left) {
        if ((rlen = read(sock, (data + sofar), left)) < 0) {
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
    int left, sofar, wlen;

    left = len;
    sofar = 0;
    while (left) {
        if ((wlen = write(sock, (data + sofar), left)) < 0) {
            fprintf(stderr, "writes: returned %d after writing %d with %d left\n",
                    wlen, sofar, left);
            return sofar;
        }
        sofar += wlen;
        left -= wlen;
    }
    return sofar;
}

static void
new_req (int fd, void *arg)
{
    int sd;
    struct sockaddr_in *serv = (struct sockaddr_in *)arg;
    uint32_t clen;
    char thefile[80], cmd_buf[300], p7[3000];
    int i, num = 0;
    unsigned char *data = NULL, *asn1 = NULL;
    uint32_t msgsinglet;
    short msglen, msgtype;
    BIO *bio = NULL;
    FILE *fp;
    struct stat blah;
    X509_REQ *req = NULL;
    EVP_ENCODE_CTX *ctx = NULL;
    
    printf("got a new request!\n");
    clen = sizeof(struct sockaddr_in);
    if ((sd = accept(fd, (struct sockaddr *)serv, &clen)) < 0) {
        return;
    }
    printf("adding %d to the service context\n", sd);

    if (reads(sd, (char *)&msgsinglet, sizeof(uint32_t)) < sizeof(uint32_t)) {
        fprintf(stderr, "didn't read a long of message length\n");
        return;
    }
    /*
     * first ushort of the singlet is the message type, next is the length
     * of the message
     */
    msgsinglet = ntohl(msgsinglet);
    msglen = (msgsinglet & 0xffff);
    msgtype = msgsinglet >> 16;
    if (msglen > 3000) {
        fprintf(stderr, "says the message is %d, calling bullshit on that\n", msglen);
        return;
    }
    if ((ctx = EVP_ENCODE_CTX_new()) == NULL) {
        goto no_cert;
    }
    if (msgtype == 1) {
        printf("the PKCS10 is gonna be %d bytes\n", msglen);
        if ((data = (unsigned char *)malloc(msglen+1)) == NULL) {
            goto no_cert;
        }
        memset(data, 0, msglen+1);
        if (reads(sd, (char *)data, msglen) < msglen) {
            fprintf(stderr, "can't read %d bytes! Bailing!\n", msglen);
            goto no_cert;
        }
        printf("PKCS10: %s\n", data);

        if ((asn1 = (unsigned char *)malloc(msglen)) == NULL) {
            fprintf(stderr, "can't malloc %d bytes\n", msglen);
            goto no_cert;
        }

        EVP_DecodeInit(ctx);
        EVP_DecodeUpdate(ctx, asn1, &i, data, msglen);
        num = i;
        EVP_DecodeFinal(ctx, &(asn1[i]), &i);
        num += i;
        free(data); data = NULL;

        if ((bio = BIO_new_mem_buf(asn1, num)) == NULL) {
            goto no_cert;
        }
        if ((req = d2i_X509_REQ_bio(bio, NULL)) == NULL) {
            fprintf(stderr, "can't convert PKCS10\n");
            goto no_cert;
        }
        BIO_free(bio); bio = NULL;

        printf("got a good CSR!\n");
    
        unique++;
        memset(thefile, 0, sizeof(thefile));
        snprintf(thefile, sizeof(thefile), "%dreq.pem", unique);
        if ((fp = fopen(thefile, "w+")) == NULL) {
            goto no_cert;
        }
        if ((bio = BIO_new(BIO_s_file())) == NULL) {
            fprintf(stderr, "unable to create bio for CSR\n");
            goto no_cert;
        }
        BIO_set_fp(bio, fp, BIO_NOCLOSE);
        PEM_write_bio_X509_REQ(bio, req);
        (void)BIO_flush(bio);
        BIO_free(bio); bio = NULL;
        fclose(fp);

        snprintf(cmd_buf, sizeof(cmd_buf),
                 "openssl ca "
                 "-policy policy_anything -batch -notext "
                 "-config ./conf/openssl.cnf "
                 "-out %dcert.pem -in %dreq.pem", unique, unique);
        if (system(cmd_buf) < 0) {
            fprintf(stderr, "can't exec '%s'\n", cmd_buf);
        }
        unlink(thefile);

        snprintf(thefile, sizeof(thefile), "%dcert.pem", unique);
        if ((stat(thefile, &blah) < 0) || (blah.st_size < 1)) {
            goto no_cert;
        }

        if (cainp7) {
            snprintf(cmd_buf, sizeof(cmd_buf),
                     "openssl crl2pkcs7 "
                     "-certfile cacert.pem -certfile %dcert.pem -outform DER -out %dder.p7 -nocrl",
                     unique, unique);
        } else {
            snprintf(cmd_buf, sizeof(cmd_buf),
                     "openssl crl2pkcs7 "
                     "-certfile %dcert.pem -outform DER -out %dder.p7 -nocrl",
                     unique, unique);
        }
        if (system(cmd_buf) < 0) {
            fprintf(stderr, "can't exec '%s'\n", cmd_buf);
        }
        unlink(thefile); 

        snprintf(thefile, sizeof(thefile), "%dder.p7", unique);
        if (stat(thefile, &blah) < 0) {
            goto no_cert;
        }
        i = blah.st_size;
        printf("DER-encoded P7 is %d bytes\n", i);
        if ((data = (unsigned char *)malloc(blah.st_size*2)) == NULL) {
            goto no_cert;
        }
        memset(data, 0, blah.st_size * 2);
    
        if ((fp = fopen(thefile, "r")) == NULL) {
            goto no_cert;
        }
        if (fread(p7, 1, sizeof(p7), fp) < blah.st_size) {
            goto no_cert;
        }
        fclose(fp);
        unlink(thefile);
        sleep(3);
    } else if (!cainp7) {
        unique++;
        memset(thefile, 0, sizeof(thefile));
        snprintf(thefile, sizeof(thefile), "%dcert.p7", unique);
        snprintf(cmd_buf, sizeof(cmd_buf),
                 "openssl crl2pkcs7 "
                 "-certfile cacert.pem -outform DER -out %s -nocrl", thefile);
        if (system(cmd_buf) < 0) {
            fprintf(stderr, "can't exec '%s'\n", cmd_buf);
        }
        if (stat(thefile, &blah) < 0) {
            goto no_cert;
        }
        i = blah.st_size;
        printf("DER-encoded CA cert in a P7 is %d bytes\n", i);
        if ((data = (unsigned char *)malloc(blah.st_size*2)) == NULL) {
            goto no_cert;
        }
        memset(data, 0, blah.st_size * 2);
    
        if ((fp = fopen(thefile, "r")) == NULL) {
            goto no_cert;
        }
        if (fread(p7, 1, sizeof(p7), fp) < blah.st_size) {
            goto no_cert;
        }
        fclose(fp);
        unlink(thefile);
    } else {
        /*
         * we're sending CA certs back as part of the p7
         */
        blah.st_size = 0;
    }
    if (blah.st_size) {
        i = 0;
        EVP_EncodeInit(ctx);
        EVP_EncodeUpdate(ctx, data, &i, (unsigned char *)p7, blah.st_size);
        num = i;
        EVP_EncodeFinal(ctx, (unsigned char *)&(data[i]), &i);
        num += i;
        printf("b64-encoded message is %d bytes\n%s\n", num, data);
    }
    msgsinglet = num;
    msgsinglet = htonl(msgsinglet);
    if (writes(sd, (char *)&msgsinglet, sizeof(int32_t)) < sizeof(int32_t)) {
        fprintf(stderr, "can't tell DPP the message is %d\n", num);
        goto no_cert;
    }
    printf("said message is %d\n", num);
    if (num) {
        if (writes(sd, (char *)data, num) < num) {
            fprintf(stderr, "can't send a %d byte message to DPP\n", num);
            goto no_cert;
        }
        printf("write %d message\n", num);
    }

no_cert:
    if (data != NULL) {
        free(data);
    }
    if (asn1 != NULL) {
        free(asn1);
    }
    if (ctx != NULL) {
        EVP_ENCODE_CTX_free(ctx);
    }
    if (bio != NULL) {
        BIO_free(bio);
    }
    srv_rem_input(srvctx, sd);
    close(sd);
    
    return;
}

static void
exceptor (int fd, void *unused)
{
    srv_rem_input(srvctx, fd);
}

int
main (int argc, char **argv)
{
    struct sockaddr_in serv;
    int opt, lsd;
    
    if (argc == 2) {
        printf("sending my cert with p7\n");
        cainp7 = 1;
    } else {
        printf("not sending my cert with p7\n");
        cainp7 = 0;
    }
    memset(&serv, 0, sizeof(struct sockaddr_in));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = INADDR_ANY;
    serv.sin_port = htons(8888);

    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    
    if ((lsd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	fprintf(stderr, "%s: unable to create enrollment socket!\n", argv[0]);
	exit(1);
    }
    opt = 1;
    if (setsockopt(lsd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)) < 0) {
	fprintf(stderr, "%s: cannot set reuseaddr on socket!\n", argv[0]);
    }

    if ((bind(lsd, (struct sockaddr *)&serv, sizeof(serv)) < 0) ||
	(listen(lsd, 5) < 0)) {
	fprintf(stderr, "%s: unable to bind and listen on enrolling socket!\n", argv[0]);
	exit(1);
    }

    if ((srvctx = srv_create_context()) == NULL) {
        fprintf(stderr, "%s: can't create service context\n", argv[0]);
        exit(1);
    }
    
    srv_add_input(srvctx, lsd, &serv, new_req);
    srv_add_exceptor(srvctx, exceptor);
    srv_main_loop(srvctx);
    exit(0);
}
