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
#ifndef _UTILS_H_

#define KID_LENGTH      43      // ceil((SHA256_DIGEST_LENGTH*4)/3) in bytes

int base64urlencode (unsigned char *burl, unsigned char *data, int len);
int base64urldecode (unsigned char *data, unsigned char *burl, int len);
int base64urlencode_verbose (unsigned char *burl, unsigned char *data, int len);
int base64urldecode_verbose (unsigned char *data, unsigned char *burl, int len);
int generate_connector (unsigned char *connector, int len, EC_GROUP *group,
                        EC_POINT *netackey, char *role, EC_KEY *signkey,
                        BN_CTX *bnctx);
int validate_connector (unsigned char *connector, int len, EC_KEY *signkey,
                        BN_CTX *bnctx);
int get_json_data (char *buf, int buflen, char **start, char **end,
                   const int nlab, ...);
int get_kid_from_point (unsigned char *kid, const EC_GROUP *group, const EC_POINT *pt,
                        BN_CTX *bnctx);
EC_POINT *get_point_from_connector (unsigned char *, int, const EC_GROUP *, BN_CTX *);

#endif  /* _UTILS_H_ */
