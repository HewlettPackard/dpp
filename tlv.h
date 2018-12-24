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

#ifndef _TLV_H_

typedef struct _tlv {
#define DPP_STATUS                      0x1000
#define INITIATOR_BOOT_HASH             0x1001
#define RESPONDER_BOOT_HASH             0x1002
#define INITIATOR_PROTOCOL_KEY          0x1003
#define WRAPPED_DATA                    0x1004
#define INITIATOR_NONCE                 0x1005
#define INITIATOR_CAPABILITIES          0x1006
#define RESPONDER_NONCE                 0x1007
#define RESPONDER_CAPABILITIES          0x1008
#define RESPONDER_PROTOCOL_KEY          0x1009
#define INITIATOR_AUTH_TAG              0x100a
#define RESPONDER_AUTH_TAG              0x100b
#define CONFIGURATION_OBJECT            0x100c
#define CONNECTOR                       0x100d
#define CONFIG_ATTRIBUTES_OBJECT        0x100e
#define BOOTSTRAP_KEY                   0x100f
#define HASH_OF_PEER_PK                 0x1010
#define HASH_OF_DEVICE_NK               0x1011
#define FINITE_CYCLIC_GROUP             0x1012
#define ENCRYPTED_KEY                   0x1013
#define ENROLLEE_NONCE                  0x1014
#define CODE_IDENTIFIER                 0x1015
#define TRANSACTION_IDENTIFIER          0x1016
#define CHANGE_CHANNEL                  0x1018
    unsigned short type;
    unsigned short length;
    unsigned char value[0];
} __attribute__ ((packed)) TLV;

#define TLV_type(x) (x)->type
#define TLV_value(x) (unsigned char *)(x)->value
#define TLV_length(x) (x)->length
#define TLV_next(x) (TLV *)(x->value + x->length)
#define TLV_lookahead(x) ((TLV *)(x->value + x->length))->type
#define TLV_type_string(x) (x)->type == DPP_STATUS ? "Status" : \
        (x)->type == INITIATOR_BOOT_HASH ? "Initiator Bootstrap Hash" : \
        (x)->type == RESPONDER_BOOT_HASH ? "Responder Bootstrap Hash" : \
        (x)->type == INITIATOR_PROTOCOL_KEY ? "Initiator Protocol Key" : \
        (x)->type == WRAPPED_DATA ? "Wrapped Data" : \
        (x)->type == INITIATOR_NONCE ? "Initiator Nonce" : \
        (x)->type == INITIATOR_CAPABILITIES ? "Initiator Capabilities" : \
        (x)->type == RESPONDER_NONCE ? "Responder Nonce" : \
        (x)->type == RESPONDER_CAPABILITIES ? "Responder Capabilities" : \
        (x)->type == RESPONDER_PROTOCOL_KEY ? "Responder Protocol Key" : \
        (x)->type == INITIATOR_AUTH_TAG ? "Initiator Authentication Tag" : \
        (x)->type == RESPONDER_AUTH_TAG ? "Responder Authentication Tag" : \
        (x)->type == FINITE_CYCLIC_GROUP ? "Finite Cyclic Group" : \
        (x)->type == ENCRYPTED_KEY ? "Encrypted Key" : \
        (x)->type == BOOTSTRAP_KEY ? "Bootstrapping Key" : \
        (x)->type == CODE_IDENTIFIER ? "PKEX Code Identifier" : \
        (x)->type == TRANSACTION_IDENTIFIER ? "Transaction Identifier" : \
        (x)->type == CHANGE_CHANNEL ? "Change Channel" : \
        "unknown"

TLV *TLV_set_tlv(TLV *, unsigned short, unsigned short, unsigned char *);
TLV *find_tlv(unsigned short, unsigned char *, int);

#endif  /* _TLV_H_ */
