#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#ifdef HASCURL
#include <curl/curl.h>
#endif /* HASCURL */
#ifdef HASAVAHI
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/timeval.h>
#endif /* HASAVAHI */

#ifdef HASAVAHI
struct resolved {
    struct resolved *next;
    char hostname[80];
    char addr[AVAHI_ADDRESS_STR_MAX];
    uint16_t port;
};

static AvahiSimplePoll *simple_poll = NULL;
#endif  /* HASAVAHI */

#ifdef HASCURL
struct buffer {
    char *ptr;
    int left;
    int txrx;
};

#define HASUSERNAME 0x01
#define HASPASSWORD 0x02
#define HASCERT 0x04
#define HASKEY 0x08
#define HASCACERT 0x10
#define HASURI 0x20
#define HASROLE 0x40
#define USESRP 0x80
int curlconfig;

char username[30], password[30], server[30], mykey[80], mycert[80], cacert[80], uridata[1000];
int port;

struct buffer recv_buff, send_buff;
CURL *curl;

/*
 * seek_cb()
 *   - callback to reset a stream that we've PUT. In this case it
 *     will be the send_buff.
 */
static int
seek_cb (void *instream, curl_off_t offset, int toseek)
{
    struct buffer *buff = (struct buffer *)instream;

    if (buff == NULL) {
        return -1;
    }
    switch (toseek) {
        case SEEK_SET:          /* rewind */
            buff->left = (buff->txrx - offset);
            buff->txrx = offset;
            break;
        case SEEK_END:          /* EOF */
            buff->txrx += buff->left;
            buff->left = 0;
            break;
        default:
        case SEEK_CUR:          /* do nothing */
            break;
    }
    return 0;   /* success! */
}

/*
 * read_cb()
 *   - callback to send data to server-- curl reads from us
 */
static size_t
read_cb (void *ptr, size_t size, size_t nmemb, void *foo)
{
    struct buffer *data = (struct buffer *)foo;
    char *src;
    int ret = 0;
    
    if (data == NULL) {
        return -1;
    }
    if (size != 1) {
        return 0;
    }
    if (data->left == 0) {
        return 0;
    }
    src = data->ptr + data->txrx;
    if (nmemb > data->left) {
        ret = data->left;
        memcpy(ptr, src, data->left);
        data->txrx += data->left;
        data->left = 0;
    } else {
        ret = nmemb;
        memcpy(ptr, src, nmemb);
        data->left -= nmemb;
        data->txrx += nmemb;
    }
    return ret;
}

/*
 * open_socket() and close_socket()
 *   - Need to keep track of whether the socket is open or not because we have
 *     no control over whether the server closes the socket each time and how
 *     and when we generate the csr depends on knowing the state of the socket.
 */
static curl_socket_t 
open_socket (void *data, curlsocktype purpose, struct curl_sockaddr *addr)
{
    int *sopen = (int *)data;
    curl_socket_t s;

    s = socket(addr->family, addr->socktype, addr->protocol);
    if (s > 0) {
        *sopen = 1;
    }
    return s;
}

static int 
close_socket (void *data, curl_socket_t s)
{
    int *sopen = (int *)data;

    close(s);
    *sopen = 0;
    return 1;
}

int
do_rest_api (char *hostname, uint16_t port)
{
    CURLcode res;
    struct curl_slist *slist = NULL;
    int socket_open = 0;
    long rcode;
    char resp[1000], cmd[250];

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    if ((curl = curl_easy_init()) == 0) {
        fprintf(stderr, "can't init curl!\n");
        return -1;
    }

    if ((curlconfig & USESRP) != USESRP) {
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3);
    } else {
        /*
         * SRP doesn't work in TLS1.3 :-(
         */
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    }        
    /*
     * reuse seems to fubar an subsequent Authorization POST, forbid it
     */
    curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);
    /*
     * ...keep track of whether the server closes the socket or 
     * not to minimize the number of CSRs we end up generating.
     */
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, open_socket);
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &socket_open);
    curl_easy_setopt(curl, CURLOPT_CLOSESOCKETFUNCTION, close_socket);
    curl_easy_setopt(curl, CURLOPT_CLOSESOCKETDATA, &socket_open);

    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 2L);
    curl_easy_setopt(curl, CURLOPT_POSTREDIR, CURL_REDIR_POST_ALL);

    if ((curlconfig & (HASKEY | HASCERT)) == (HASKEY | HASCERT)) {
        curl_easy_setopt(curl, CURLOPT_SSLKEY, mykey);
        curl_easy_setopt(curl, CURLOPT_SSLCERT, mycert);
        curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);
    }
    if ((curlconfig & HASCACERT) == HASCACERT) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, cacert);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    } else {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    
    if ((curlconfig & (HASUSERNAME | HASPASSWORD)) == (HASUSERNAME | HASPASSWORD)) {
        if (curlconfig & USESRP) {
            curl_easy_setopt(curl, CURLOPT_TLSAUTH_TYPE, "SRP");
            curl_easy_setopt(curl, CURLOPT_TLSAUTH_USERNAME, username);
            curl_easy_setopt(curl, CURLOPT_TLSAUTH_PASSWORD, password);
        } else {
            curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC|CURLAUTH_DIGEST);
            curl_easy_setopt(curl, CURLOPT_USERNAME, username);
            curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
        }
    }
    
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    memset(resp, 0, sizeof(resp));
    recv_buff.ptr = resp;
    recv_buff.left = sizeof(resp);
    recv_buff.txrx = 0;

    printf("sending URI to %s on port %u\n", hostname, port);
    sprintf(cmd, "https://%s:%d/dpp/bskey", hostname, port);

    curl_easy_setopt(curl, CURLOPT_URL, cmd);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_cb);
    curl_easy_setopt(curl, CURLOPT_READDATA, &send_buff);

    curl_easy_setopt(curl, CURLOPT_SEEKFUNCTION, seek_cb);
    curl_easy_setopt(curl, CURLOPT_SEEKDATA, &send_buff);

    slist = curl_slist_append(slist, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

    send_buff.ptr = uridata;
    send_buff.left = strlen(uridata);
    send_buff.txrx = 0;
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, send_buff.left);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &rcode);

    if (rcode == 401) {
        /*
         * pray that something was configured and it works....
         */
        curl_easy_setopt(curl, CURLOPT_USERNAME, username);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC|CURLAUTH_DIGEST);
        send_buff.txrx = 0;
        curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &rcode);
    }        

    curl_slist_free_all(slist);
    if (rcode != 200) {
        fprintf(stderr, "unable to add DPP URI, response code is %ld\n", rcode);
    } else {
        fprintf(stderr, "success, res = %d!\n", res);
    }

    return rcode;
}
#endif  /* HASCURL */

#ifdef HASAVAHI
static void
resolve_cb (AvahiServiceResolver *res, AvahiIfIndex ifidx, AvahiProtocol proto, AvahiResolverEvent event,
            const char *name, const char *type, const char *domain, const char *hostname,
            const AvahiAddress *addr, uint16_t port, AvahiStringList *txt, AvahiLookupResultFlags flags,
            void *userdata)
{
    struct resolved *serv;
    char *t;

    if (res == NULL) {
        return;
    }
    serv = (struct resolved *)userdata;
    if (serv == NULL) {
        fprintf(stderr, "trying to resolve to NULL data\n");
        return;\
    }
    switch (event) {
        case AVAHI_RESOLVER_FAILURE:
            fprintf(stderr, "failed to resolve service '%s' of type '%s' in domain '%s' (error %s)\n",
                    name, type, domain, avahi_strerror(avahi_client_errno(avahi_service_resolver_get_client(res))));
            strcpy(serv->hostname, "ERR");
            serv->port = -1;
            break;
        case AVAHI_RESOLVER_FOUND:
            /*
             * record our resolved service....
             */
            avahi_address_snprint(serv->addr, sizeof(serv->addr), addr);
            t = avahi_string_list_to_string(txt);
            printf("resolved service '%s' of type '%s' in domain '%s' to %s on port %u (%s)\nTXT record: %s\n",
                   name, type, domain, hostname, port, serv->addr, t);
            strcpy(serv->hostname, hostname);
            serv->port = port;
            avahi_free(t);
            break;
    }
    avahi_service_resolver_free(res);
}

/*
 * free up the structures we allocated for each service we browsed
 */
static void
free_servs (struct resolved *serv)
{
    if (serv == NULL) {
        return;
    }
    if (serv->next != NULL) {
        free_servs(serv->next);
    }
    free(serv);
    serv = NULL;
    return;
}

/*
 * kill this off gracefully...
 */
static void
suicide (AvahiTimeout *to, void *unused)
{
    avahi_simple_poll_quit(simple_poll);
    return;
}

static void
browse_cb (AvahiServiceBrowser *browser, AvahiIfIndex ifidx, AvahiProtocol proto, AvahiBrowserEvent event,
           const char *name, const char *type, const char *domain, AvahiLookupResultFlags flags, void *userdata)
{
    static struct resolved *servs = NULL;
    struct resolved *serv;
    struct timeval tv;
    AvahiClient *client = (AvahiClient *)userdata;

    if (browser == NULL) {
        return;
    }
    switch (event) {
        case AVAHI_BROWSER_FAILURE:
            fprintf(stderr, "avahi browse failure\n");
            avahi_simple_poll_quit(simple_poll);
            break;
        case AVAHI_BROWSER_NEW:
            /*
             * allocate struct to resolve this service
             */
            if (servs == NULL) {
                if ((servs = (struct resolved *)malloc(sizeof(struct resolved))) == NULL) {
                    fprintf(stderr, "can't allocate resolved data\n");
                    return;
                }
                serv = servs;
            } else {
                for (serv = servs; serv != NULL; serv = serv->next) {
                    if (serv->next == NULL) {
                        if ((serv->next = (struct resolved *)malloc(sizeof(struct resolved))) == NULL) {
                            fprintf(stderr, "can't allocate more resolved data\n");
                            return;
                        }
                        serv = serv->next;
                        break;
                    }
                }
            }
            if (serv == NULL) {
                fprintf(stderr, "bad allocation of resolved data\n");
                return;
            }
            printf("new DPP service '%s' of type '%s' in domain '%s' found\n", name, type, domain);
            if (!avahi_service_resolver_new(client, ifidx, proto, name, type, domain,
                                            AVAHI_PROTO_UNSPEC, 0, resolve_cb, serv)) {
                fprintf(stderr, "failed to resolve service '%s' (error %s)\n", name,
                        avahi_strerror(avahi_client_errno(client)));
            }
            break;
        case AVAHI_BROWSER_REMOVE:
            break;
        case AVAHI_BROWSER_CACHE_EXHAUSTED:
            break;
        case AVAHI_BROWSER_ALL_FOR_NOW:
            if (servs == NULL) {
                printf("no service found for DPP bootstrapping :-(\n");
#ifdef HASCURL
                /*
                 * see if there's anything we can do....
                 */
                do_rest_api(server, port);
#endif  /* HASCURL */                
                return;
            }
            for (serv = servs; serv != NULL; serv = serv->next) {
                printf("Resolved %s (%s) at %u...\n", serv->hostname, serv->addr, serv->port);
            }
#ifdef HASCURL
            do_rest_api((char *)servs->hostname, servs->port);
#endif  /* HASCURL */
            free_servs(servs);
            avahi_simple_poll_get(simple_poll)->timeout_new(avahi_simple_poll_get(simple_poll),
                                                            avahi_elapse_time(&tv, 1000, 0),
                                                            suicide, NULL);
            break;
    }
    return;
}

static void
client_cb (AvahiClient *c, AvahiClientState state, void *unused)
{
    if (c == NULL) {
        return;
    }
    if (state == AVAHI_CLIENT_FAILURE) {
        avahi_simple_poll_quit(simple_poll);
    }
}

int
main (int argc, char **argv)
{
    char uri[250], role[30];
    AvahiClient *client = NULL;
    AvahiServiceBrowser *sb = NULL;
    char *serv = "_bootstrapping._sub._dpp._tcp";       // all we're interested in
    int err, c;
    
    memset(username, 0, sizeof(username));
    memset(password, 0, sizeof(password));
    memset(server, 0, sizeof(server));
    memset(mycert, 0, sizeof(mycert));
    memset(mykey, 0, sizeof(mykey));
    memset(cacert, 0, sizeof(cacert));
    strcpy(server, "localhost");
    port = 443;
    curlconfig = 0;
    for (;;) {
        c = getopt(argc, argv, "u:p:s:c:k:w:q:a:hxr:");
        if (c < 0) {
            break;
        }
        switch (c) {
            case 'u':
                curlconfig |= HASUSERNAME;
                strcpy(username, optarg);
                break;
            case 'p':
                curlconfig |= HASPASSWORD;
                strcpy(password, optarg);
                break;
            case 's':
                strcpy(server, optarg);
                printf("%s: server %s may be overridden by MDNS browsing...\n", argv[0], server);
                break;
            case 'c':
                curlconfig |= HASCERT;
                strcpy(mycert, optarg);
                break;
            case 'k':
                curlconfig |= HASKEY;
                strcpy(mykey, optarg);
                break;
            case 'a':
                curlconfig |= HASCACERT;
                strcpy(cacert, optarg);
                break;
            case 'w':
                port = atoi(optarg);
                break;
            case 'q':
                strcpy(uri, optarg);
                curlconfig |= HASURI;
                break;
            case 'r':
                strcpy(role, optarg);
                curlconfig |= HASROLE;
                break;
            case 'x':
                curlconfig |= USESRP;
                break;
            case 'h':
            default:
                fprintf(stderr,
                        "USAGE: %s [-hupsckwq]\n"
                        "\t-h  show usage, and exit\n"
                        "\t-u <username> for username/password authentication to service\n"
                        "\t-p <password> for username/password authentication to service\n"
                        "\t-s <server> name of server (may be overridden by MDNS)\n"
                        "\t-w <num> the port number on server (may be overridden by MDNS)\n"
                        "\t-k <filename> keyfile for cert-based authentication to service\n"
                        "\t-c <filename> certificate for cert-based authentication to service\n"
                        "-t-a <filename> CA certificate\n"
                        "\t-x  use TLS-SRP to authenticate (requires username and password too)\n"
                        "\t-q <string> the DPP URI to send to the service, this is mandatory\n"
                        "\t-r <role> the role the device should take-- STA, AP, or Configurator\n",
                        argv[0]);
                goto fin;
        }
    }
    if (((curlconfig & (HASUSERNAME | HASPASSWORD)) != (HASUSERNAME | HASPASSWORD)) &&
        ((curlconfig & USESRP) != USESRP) &&
        ((curlconfig & (HASCERT | HASKEY)) != (HASCERT | HASKEY))) {
        fprintf(stderr, "%s: need to specify authentication, basic with username/password, SRP with username/password or key/cert\n", argv[0]);
        goto fin;
    }
    if ((curlconfig & HASURI) == 0) {
        fprintf(stderr, "%s: need to specify a DPP URI using -q\n", argv[0]);
        goto fin;
    }
    if (curlconfig & HASROLE) {
        snprintf(uridata, sizeof(uridata), "{\"dppUri\":\"%s\",\"dppRole\":\"%s\"}", uri, role);
    } else {
        snprintf(uridata, sizeof(uridata), "{\"dppUri\":\"%s\"}", uri);
    }
    if ((simple_poll = avahi_simple_poll_new()) == NULL) {
        fprintf(stderr, "%s: unable to create avahi simple poll!\n", argv[0]);
        goto fin;
    }
    if ((client = avahi_client_new(avahi_simple_poll_get(simple_poll), 0, client_cb, NULL, &err)) == NULL) {
        fprintf(stderr, "%s: unable to create avahi client!\n", argv[0]);
        goto fin;
    }
    if ((sb = avahi_service_browser_new(client, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, serv, NULL, 0,
                                        browse_cb, client)) == NULL) {
        fprintf(stderr, "%s: unable to create avahi service browser!\n", argv[0]);
        goto fin;
    }
    avahi_simple_poll_loop(simple_poll);

fin:    
    printf("fin!\n");
    if (sb != NULL) {
        avahi_service_browser_free(sb);
    }
    if (client != NULL) {
        avahi_client_free(client);
    }
    if (simple_poll != NULL) {
        avahi_simple_poll_free(simple_poll);
    }
    exit(0);
}
#else   /* not HASAVAHI */
int
main (int argc, char **argv)
{
    char uri[250], role[30];
#ifdef HASCURL
    int c;
    
    printf("enabling AVAHI will allow you to discover the bootstrap service\n");
    memset(username, 0, sizeof(username));
    memset(password, 0, sizeof(password));
    memset(server, 0, sizeof(server));
    memset(mycert, 0, sizeof(mycert));
    memset(mykey, 0, sizeof(mykey));
    memset(cacert, 0, sizeof(cacert));
    strcpy(server, "localhost");
    port = 443;
    memset(dppuri, 0, sizeof(dppuri));
    curlconfig = 0;
    for (;;) {
        c = getopt(argc, argv, "u:p:s:c:k:w:q:a:hr:");
        if (c < 0) {
            break;
        }
        switch (c) {
            case 'u':
                curlconfig |= HASUSERNAME;
                strcpy(username, optarg);
                break;
            case 'p':
                curlconfig |= HASPASSWORD;
                strcpy(password, optarg);
                break;
            case 's':
                strcpy(server, optarg);
                printf("%s: server %s may be overridden by MDNS browsing...\n", argv[0], server);
                break;
            case 'c':
                curlconfig |= HASCERT;
                strcpy(mycert, optarg);
                break;
            case 'k':
                curlconfig |= HASKEY;
                strcpy(mykey, optarg);
                break;
            case 'a':
                curlconfig |= HASCACERT;
                strcpy(cacert, optarg);
                break;
            case 'w':
                port = atoi(optarg);
                break;
            case 'q':
                strcpy(uri, optarg);
                curlconfig |= HASURI;
                break;
            case 'r':
                strcpy(role, optarg);
                curlconfig |= HASROLE;
                break;
            case 'h':
            default:
                fprintf(stderr,
                        "USAGE: %s [-hupsckwq]\n"
                        "\t-h  show usage, and exit\n"
                        "\t-u <username> for username/password authentication to service\n"
                        "\t-p <password> for username/password authentication to service\n"
                        "\t-s <server> name of server (may be overridden by MDNS)\n"
                        "\t-w <num> the port number on which the server is providing service\n"
                        "\t-k <filename> location of keyfile for cert-based authentication to service\n"
                        "\t-c <filename> location of certificate for cert-based authentication to service\n"
                        "\t-q <string> the DPP URI to send to the service, this is mandatory\n"
                        "\t-r <role> the role the device should take-- STA, AP, or Configurator\n",
                        argv[0]);
                goto fin;
        }
    }
    if (((curlconfig & (HASUSERNAME | HASPASSWORD)) != (HASUSERNAME | HASPASSWORD)) &&
        ((curlconfig & (HASCERT | HASKEY)) != (HASCERT | HASKEY))) {
        fprintf(stderr, "%s: need to specify authentication, either username/password or key/cert\n", argv[0]);
        goto fin;
    }
    if ((curlconfig & HASURI) == 0) {
        fprintf(stderr, "%s: need to specify a DPP URI using -q\n", argv[0]);
        goto fin;
    }
    if (curlconfig & HASROLE) {
        snprintf(uridata, sizeof(uridata), "{\"dppUri\":\"%s\",\"dppRole\":\"%s\"}", uri, role);
    } else {
        snprintf(uridata, sizeof(uridata), "{\"dppUri\":\"%s\"}", uri);
    }

    do_rest_api(server, port);
fin:
#else
    printf("need to enable CURL to talk to the service!\n");
#endif  /* HASCURL */    
    exit(0);
}
#endif  /* HASAVAHI */
