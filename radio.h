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

#ifndef _RADIO_H_

/*
 * Support for Atherois radio on FreeBSD
 */

#define RADIO_STA       0
#define RADIO_ADHOC     1
#define RADIO_HOSTAP    2
#define RADIO_MONITOR   3
#define RADIO_IBSS      4
#define RADIO_11a       1
#define RADIO_11b       2
#define RADIO_11g       3

struct _regulatory {
    unsigned char class;
    int band;
    unsigned char channel;
} regulatory[] = {
    { 115, RADIO_11a, 36 },
    { 115, RADIO_11a, 40 },
    { 115, RADIO_11a, 44 },
    { 115, RADIO_11a, 48 },
    { 118, RADIO_11a, 52 },
    { 118, RADIO_11a, 56 },
    { 118, RADIO_11a, 60 },
    { 118, RADIO_11a, 64 },
    { 124, RADIO_11a, 149 },
    { 124, RADIO_11a, 153 },
    { 124, RADIO_11a, 157 },
    { 124, RADIO_11a, 161 },
    { 121, RADIO_11a, 100 },
    { 121, RADIO_11a, 104 },
    { 121, RADIO_11a, 108 },
    { 121, RADIO_11a, 112 },
    { 121, RADIO_11a, 116 },
    { 121, RADIO_11a, 120 },
    { 121, RADIO_11a, 124 },
    { 121, RADIO_11a, 128 },
    { 121, RADIO_11a, 132 },
    { 121, RADIO_11a, 136 },
    { 121, RADIO_11a, 140 },
    { 121, RADIO_11a, 144 },
    { 125, RADIO_11a, 149 },
    { 121, RADIO_11a, 153 },
    { 121, RADIO_11a, 157 },
    { 121, RADIO_11a, 161 },
    { 121, RADIO_11a, 165 },
    { 81, RADIO_11g, 1 },
    { 81, RADIO_11g, 2 },
    { 81, RADIO_11g, 3 },
    { 81, RADIO_11g, 4 },
    { 81, RADIO_11g, 5 },
    { 81, RADIO_11g, 6 },
    { 81, RADIO_11g, 7 },
    { 81, RADIO_11g, 8 },
    { 81, RADIO_11g, 9 },
    { 81, RADIO_11g, 10 },
    { 81, RADIO_11g, 11 },
    { 116, RADIO_11a, 36 },
    { 116, RADIO_11a, 44 },
    { 119, RADIO_11a, 52 },
    { 119, RADIO_11a, 60 },
    { 122, RADIO_11a, 100 },
    { 122, RADIO_11a, 108 },
    { 122, RADIO_11a, 116 },
    { 122, RADIO_11a, 124 },
    { 122, RADIO_11a, 132 },
    { 122, RADIO_11a, 140 },
    { 126, RADIO_11a, 149 },
    { 126, RADIO_11a, 157 },
    { 117, RADIO_11a, 40 },
    { 117, RADIO_11a, 48 },
    { 120, RADIO_11a, 56 },
    { 120, RADIO_11a, 64 },
    { 123, RADIO_11a, 104 },
    { 123, RADIO_11a, 112 },
    { 123, RADIO_11a, 120 },
    { 123, RADIO_11a, 128 },
    { 123, RADIO_11a, 136 },
    { 123, RADIO_11a, 144 },
    { 127, RADIO_11a, 153 },
    { 127, RADIO_11a, 161 },
    { 83, RADIO_11g, 1 },
    { 83, RADIO_11g, 2 },
    { 83, RADIO_11g, 3 },
    { 83, RADIO_11g, 4 },
    { 83, RADIO_11g, 5 },
    { 83, RADIO_11g, 6 },
    { 83, RADIO_11g, 7 },
    { 84, RADIO_11g, 5 },
    { 84, RADIO_11g, 6 },
    { 84, RADIO_11g, 7 },
    { 84, RADIO_11g, 8 },
    { 84, RADIO_11g, 9 },
    { 84, RADIO_11g, 10 },
    { 84, RADIO_11g, 11 },
    { 128, RADIO_11a, 42 },
    { 128, RADIO_11a, 58 },
    { 128, RADIO_11a, 106 },
    { 128, RADIO_11a, 122 },
    { 128, RADIO_11a, 138 },
    { 128, RADIO_11a, 155 }
};

#endif  /* _RADIO_H */
