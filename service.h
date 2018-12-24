/*
 * Copyright (c) Dan Harkins, 2008, 2009, 2010
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
 *     3. All advertising materials and documentation mentioning features
 *	  or use of this software must display the following acknowledgement:
 *
 *        "This product includes software written by
 *         Dan Harkins (dharkins at lounge dot org)"
 *
 *  "DISCLAIMER OF LIABILITY
 *  
 *  THIS SOFTWARE IS PROVIDED BY DAN HARKINS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL DAN HARKINS BE LIABLE
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

#ifndef _SERVICE_CONTEXT_H_
#define _SERVICE_CONTEXT_H_

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

typedef unsigned int timerid;
/*
 * input callbacks and timer callbacks
 */
typedef void (*fdcb)(int fd, void *data);
typedef void (*timercb)(timerid id, void *data);
typedef void (*dumpcb)(timerid id, int num, int secs, int usecs, char *msg);

/*
 * a timer definition
 */
struct timer {
    struct timeval to;
    timercb proc;
    timerid id;
    void *data;
};

#define SRV_SEC(x)	((x) * 1000000)
#define SRV_MSEC(x)	((x) * 1000)
#define SRV_USEC(x)	x

/*
 * an I/O definition
 */
struct source {
    int fd;
    fdcb proc;
    void *data;
};

/*
 * the number of timers and file descriptors we'll dispatch
 * are fixed. If you hit that ceiling bump here.
 */
#define NTIMERS		1024
#define NFDS		128

/*
 * a service context
 */
typedef struct _servcxt {
    fd_set readfds;
    fd_set writefds;
    fd_set exceptfds;
    timerid timer_id;
    struct timeval gbl_timer;
    fdcb exceptor;
    int ntimers;
    struct timer timers[NTIMERS];
    int ninputs;
    struct source inputs[NFDS];
    int noutputs;
    struct source outputs[NFDS];
} servcxt;

typedef struct _servcxt *service_context;

/*
 * service context APIs 
 */
timerid srv_add_timeout(service_context, unsigned long, timercb, void *);

int srv_rem_timeout(service_context, timerid);

void srv_dump_timeouts(service_context, dumpcb, char *);

int srv_add_input(service_context, int, void *, fdcb);

void srv_rem_input(service_context, int);

int srv_add_output(service_context, int, void *, fdcb);

void srv_rem_output(service_context, int);

void srv_add_exceptor(service_context, fdcb);

int srv_main_loop(service_context);

service_context srv_create_context(void);

#endif	/* _SERVICE_CONTEXT_H_ */

