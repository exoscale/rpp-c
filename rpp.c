/*
 *
 * riemann persistent ping, see https://github.com/exoscale/rpp-c
 *
 * Copyright (c) 2016 Exoscale
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/queue.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <err.h>
#include <limits.h>
#include <oping.h>
#include <bsd/string.h>
#include <bsd/stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <riemann/riemann-client.h>

#define RIEMANN_SERVICE_MAX     64
#define RIEMANN_PROTO_MAX       4
#define RIEMANN_TAG_MAX         512
#define RIEMANN_ATTR_MAX        512
#define CONFIG_LINE_MAX         2048
#define DEFAULT_INTERVAL        60
#define ITERATOR_BUFFER_SIZE    2048

int debug = 0;

struct riemann_attr {
    char   key[PATH_MAX];
    char   val[PATH_MAX];
};

struct host {
    TAILQ_ENTRY(host)    entry;
    char                 hostname[HOST_NAME_MAX];
    char		 displayname[HOST_NAME_MAX];
    int                  seen;
};

enum riemann_proto {
    RIEMANN_PROTO_TCP = 0,
    RIEMANN_PROTO_UDP,
    RIEMANN_PROTO_TLS
};

struct rpp {
    enum riemann_proto           riemann_proto;
    char                         riemann_host[HOST_NAME_MAX];
    in_port_t                    riemann_port;
    char                         riemann_ca_cert[PATH_MAX];
    char                         riemann_cert[PATH_MAX];
    char                         riemann_cert_key[PATH_MAX];
    char                         riemann_service[RIEMANN_SERVICE_MAX];
    int                          riemann_tag_count;
    char                        *riemann_tags[RIEMANN_TAG_MAX];
    int                          riemann_attr_count;
    struct riemann_attr          riemann_attrs[RIEMANN_ATTR_MAX];
    int                          riemann_ttl;
    double                       ping_timeout;
    int                          ping_ttl;
    int                          interval;
    TAILQ_HEAD(host_list, host)  hosts;
    pingobj_t                   *po;
    riemann_client_t            *rclient;
};

void             usage(void);
void             parse_configuration_line(struct rpp *, const char *, char *);
void             parse_configuration(struct rpp *, const char *);
void             dump_configuration(struct rpp *);
void             rpp_add_hosts(struct rpp *);
void             rpp_remove_hosts(struct rpp *);
const char	*rpp_set_host_seen(struct host_list *, const char *);
riemann_event_t *rpp_riemann_event(struct rpp *, const char *);
void             rpp_send_messages(struct rpp *);
void             rpp_riemann_client(struct rpp *);

/*
 * Die, explaining our usage.
 */
void
usage(void) {
    fprintf(stderr, "usage: rpp <config file path>\n");
    fprintf(stderr, "  [NOTE]: you may set the RPP_DEBUG environment variable\n");
    errx(1, "usage: rpp <config file path>");
}

/*
 * Parse a configuration line.
 * This parser is awfully minimal and will only allow for one whitespace char
 * between a configuration directive and its value. Additionaly, no trimming is
 * done on either keys or values.
 */
void
parse_configuration_line(struct rpp *env, const char *key, char *val)
{
    const char          *errstr = NULL;
    struct riemann_attr *attr = NULL;
    struct host         *host = NULL;
    size_t               off, len;

    if (strcasecmp(key, "riemann-proto") == 0) {
        if (strcasecmp(val, "tcp") == 0) {
            env->riemann_proto = RIEMANN_PROTO_TCP;
        } else if (strcasecmp(val, "udp")) {
            env->riemann_proto = RIEMANN_PROTO_UDP;
        } else if (strcasecmp(val, "tls")) {
            env->riemann_proto = RIEMANN_PROTO_TLS;
        } else {
            errx(1, "invalid riemann protocol: %s", val);
        }
    } else if (strcasecmp(key, "riemann-host") == 0) {
        if (strlcpy(env->riemann_host, val, sizeof(env->riemann_host)) >=
            sizeof(env->riemann_host))
            errx(1, "riemann host truncated: %s", val);
    } else if (strcasecmp(key, "riemann-port") == 0) {
        env->riemann_port = (in_port_t)strtonum(val, 1, 65535, &errstr);
        if (errstr != NULL) {
            errx(1, "invalid port: %s", val);
        }
    } else if (strcasecmp(key, "riemann-ca-cert") == 0) {
        if (strlcpy(env->riemann_ca_cert, val, sizeof(env->riemann_ca_cert)) >=
            sizeof(env->riemann_ca_cert)) {
            errx(1, "ca certificate path truncated: %s", val);
        }
    } else if (strcasecmp(key, "riemann-cert") == 0) {
        if (strlcpy(env->riemann_cert, val, sizeof(env->riemann_cert)) >=
            sizeof(env->riemann_cert)) {
            errx(1, "certificate path truncated: %s", val);
        }
    } else if (strcasecmp(key, "riemann-cert-key") == 0) {
        if (strlcpy(env->riemann_cert_key, val, sizeof(env->riemann_cert_key)) >=
            sizeof(env->riemann_cert_key)) {
            errx(1, "certificate key path truncated: %s", val);
        }
    } else if (strcasecmp(key, "riemann-service") == 0) {
        if (strlcpy(env->riemann_service, val, sizeof(env->riemann_service)) >=
            sizeof(env->riemann_service)) {
            errx(1, "service name truncatd: %s", val);
        }
    } else if (strcasecmp(key, "riemann-tag") == 0) {
        if (env->riemann_tag_count >= RIEMANN_TAG_MAX)
            errx(1, "too many tags");
        if ((env->riemann_tags[env->riemann_tag_count++] = strdup(val)) == NULL) {
            err(1, "cannot allocate tag");
        }
    } else if (strcasecmp(key, "riemann-attr") == 0) {
        if (env->riemann_attr_count >= RIEMANN_ATTR_MAX)
            errx(1, "too many attributes");

        off = strcspn(val, " \t");
        if (off == strlen(val)) {
            errx(1, "invalid attribute: %s", val);
        }
        val[off] = '\0';
        off++;
        attr = &env->riemann_attrs[env->riemann_attr_count];
        if (strlcpy(attr->key, val, sizeof(attr->key)) >= sizeof(attr->key)) {
            errx(1, "attribute key truncated");
        }
        val += off;
        if (strlcpy(attr->val, val, sizeof(attr->val)) >= sizeof(attr->val)) {
            errx(1, "attribute val truncated");
        }
        env->riemann_attr_count++;
    } else if (strcasecmp(key, "riemann-ttl") == 0) {
        env->riemann_ttl = (int)strtonum(val, 1, INT_MAX, &errstr);
        if (errstr != NULL) {
            errx(1, "invalid riemann ttl: %s", val);
        }
    } else if (strcasecmp(key, "ping-timeout") == 0) {
        env->ping_timeout = (double)strtonum(val, 1, INT_MAX, &errstr);
        if (errstr != NULL) {
            errx(1, "invalid ping timeout: %s", val);
        }
    } else if (strcasecmp(key, "ping-ttl") == 0) {
        env->ping_ttl = (int)strtonum(val, 1, 255, &errstr);
        if (errstr != NULL) {
            errx(1, "invalid ping ttl: %s", val);
        }
    } else if (strcasecmp(key, "interval") == 0) {
        env->interval = (int)strtonum(val, 1, INT_MAX, &errstr);
        if (errstr != NULL) {
            errx(1, "invalid ping ttl: %s", val);
        }
    } else if (strcasecmp(key, "host") == 0) {
        if ((host = calloc(1, sizeof(*host))) == NULL) {
            err(1, "cannot allocate host");
        }
        len = strlen(val);
        off = strcspn(val, " \t");
        val[off] = '\0';
        if (strlcpy(host->hostname, val, sizeof(host->hostname)) >=
            sizeof(host->hostname)) {
            errx(1, "host name truncated");
        }
        if (len != off) {
            /* Optional display name */
            off++;
            off += strspn(val + off, " \t");
            val += off; len -= off;
            off = strcspn(val, " \t");
            val[off] = '\0';
            if (len != off) {
                errx(1, "too many arguments for host: %s", val);
            }
            if (strlcpy(host->displayname, val, sizeof(host->displayname)) >=
                sizeof(host->displayname)) {
                errx(1, "display name truncated");
            }
        }
        TAILQ_INSERT_TAIL(&env->hosts, host, entry);
    } else {
        errx(1, "invalid configuration key: %s", key);
    }
}

/*
 * Parse a configuration file and feed valid lines to parse_configuration_line.
 * Empty lines and lines starting with # are ignored.
 */
void
parse_configuration(struct rpp *env, const char *path)
{
    FILE    *f;
    char    *line;
    size_t   len;
    ssize_t  br;
    char    *key;
    char    *val;
    size_t   off;

    (void)strlcpy(env->riemann_service, "ping", sizeof(env->riemann_service));
    TAILQ_INIT(&env->hosts);
    env->ping_timeout = PING_DEF_TIMEOUT;
    env->ping_ttl = PING_DEF_TTL;
    env->interval = DEFAULT_INTERVAL;

    if ((f = fopen(path, "r")) == NULL)
        err(1, "cannot open configuration: %s", path);

    for (line = NULL, len = 0; (br = getline(&line, &len, f)) != -1;) {

        if (len >= CONFIG_LINE_MAX) {
            errx(1, "configuration line too long");
        }
        line[strcspn(line, "\r\n")] = '\0';

        if ((line[strspn(line, " \t")] == '\0') ||
            (line[strspn(line, " \t")] == '#')) {
            free(line);
            line = NULL;
            continue;
        }

        off = strcspn(line, "\t ");

        if (off >= strlen(line))
            errx(1, "invalid configuration line: %s", line);

        line[off] = '\0';
        off++;
        key = line;
        val = line + off;
        parse_configuration_line(env, key, val);
        free(line);
        line = NULL;
    }

    free(line);
    fclose(f);
}

/*
 * Add our configured hosts to the liboping object.
 * We only notify insertion errors. A critical event
 * will be sent for missed insertion as we compare list members
 * once the ping run is done.
 */
void
rpp_add_hosts(struct rpp *env) {
    struct host *h;

    TAILQ_FOREACH(h, &env->hosts, entry) {
        if (ping_host_add(env->po, h->hostname) != 0) {
            fprintf(stderr, "cannot add ping host: %s: %s\n",
                    h->hostname,
                    ping_get_error(env->po));
        }
    }
}

/*
 * Remove hosts from the liboping object.
 */
void
rpp_remove_hosts(struct rpp *env) {
    struct host *h;

    TAILQ_FOREACH(h, &env->hosts, entry) {
        ping_host_remove(env->po, h->hostname);
    }
}

/*
 * Set a host's seen flag to true.
 */
const char *
rpp_set_host_seen(struct host_list *hosts, const char *hostname) {
    struct host *h;

    TAILQ_FOREACH(h, hosts, entry) {
        if (strncmp(h->hostname, hostname, strlen(h->hostname)) == 0) {
            h->seen = 1;
            return strlen(h->displayname)?h->displayname:h->hostname;
        }
    }
    errx(1, "unknown host: %s", hostname);
}

/*
 * Return a riemann event with common fields already set to
 * appropriate values.
 */
riemann_event_t *
rpp_riemann_event(struct rpp *env, const char *hostname)
{

    int i;
    riemann_event_t *re;
    char             service[PATH_MAX];

    (void)strlcpy(service, env->riemann_service, sizeof(service));

    if ((re = riemann_event_create(RIEMANN_EVENT_FIELD_HOST,
                                   hostname,
                                   RIEMANN_EVENT_FIELD_SERVICE,
                                   service,
                                   RIEMANN_EVENT_FIELD_TTL,
                                   env->riemann_ttl,
                                   RIEMANN_EVENT_FIELD_TIME,
                                   (int64_t)time(NULL),
                                   RIEMANN_EVENT_FIELD_NONE)) == NULL)
        err(1, "cannot allocate riemann event");

    for (i = 0; i < env->riemann_tag_count; i++) {
        riemann_event_tag_add(re, env->riemann_tags[i]);
    }
    for (i = 0; i < env->riemann_attr_count; i++) {
        riemann_event_string_attribute_add(re,
                                           env->riemann_attrs[i].key,
                                           env->riemann_attrs[i].val);
    }
    return re;
}

/*
 * This is the workhorse function:
 *
 * - Creates a riemann message.
 * - Sets all hosts as unseen.
 * - Iterates over the result, appending riemann events and marking hosts seen.
 * - Iterates over unseen hosts, appending a riemann event as well.
 * - Connects to riemann.
 * - Send messags.
 * - Disconnects from riemann.
 */
void
rpp_send_messages(struct rpp *env)
{
    struct host         *h;
    pingobj_iter_t      *it;
    char                 hostname[ITERATOR_BUFFER_SIZE];
    riemann_message_t   *rm;
    riemann_event_t     *re;
    double               latency;
    int                  e;
    size_t               len;
    const char		*displayname;

    if ((rm = riemann_message_new()) == NULL)
        err(1, "cannot allocate riemann message");

    TAILQ_FOREACH(h, &env->hosts, entry) {
        h->seen = 0;
    }

    for (it =  ping_iterator_get(env->po);
         it != NULL;
         it = ping_iterator_next(it)) {

        bzero(hostname, sizeof(hostname));

        len = sizeof(hostname);
        ping_iterator_get_info(it, PING_INFO_USERNAME, hostname, &len);

        displayname = rpp_set_host_seen(&env->hosts, hostname);

        len = sizeof(latency);
        ping_iterator_get_info(it, PING_INFO_LATENCY, &latency, &len);


        re = rpp_riemann_event(env, displayname);

        riemann_event_set(re,
                          RIEMANN_EVENT_FIELD_STATE,
                          (latency >= 0) ? "ok" : "critical",
                          RIEMANN_EVENT_FIELD_METRIC_D,
                          latency,
                          RIEMANN_EVENT_FIELD_STRING_ATTRIBUTES,
                          "lost", "false", NULL,
                          RIEMANN_EVENT_FIELD_NONE);
        riemann_message_append_events(rm, re, NULL);
    }

    TAILQ_FOREACH(h, &env->hosts, entry) {
        if (!h->seen) {
            displayname = strlen(h->displayname)?h->displayname:h->hostname;
            re = rpp_riemann_event(env, displayname);
            riemann_event_set(re,
                              RIEMANN_EVENT_FIELD_STATE,
                              "critical",
                              RIEMANN_EVENT_FIELD_METRIC_D,
                              0.0,
                              RIEMANN_EVENT_FIELD_STRING_ATTRIBUTES,
                              "lost", "true", NULL,
                              RIEMANN_EVENT_FIELD_NONE);
            riemann_message_append_events(rm, re, NULL);
        }
    }

    e = 0;
    switch (env->riemann_proto) {
    case RIEMANN_PROTO_TCP:
        e = riemann_client_connect(env->rclient,
                                   RIEMANN_CLIENT_TCP,
                                   env->riemann_host,
                                   env->riemann_port);
        break;
    case RIEMANN_PROTO_UDP:
        e = riemann_client_connect(env->rclient,
                                   RIEMANN_CLIENT_UDP,
                                   env->riemann_host,
                                   env->riemann_port);
        break;
    case RIEMANN_PROTO_TLS:
        e = riemann_client_connect(env->rclient,
                                   RIEMANN_CLIENT_TLS,
                                   env->riemann_host,
                                   env->riemann_port,
                                   RIEMANN_CLIENT_OPTION_TLS_CA_FILE,
                                   env->riemann_ca_cert,
                                   RIEMANN_CLIENT_OPTION_TLS_CERT_FILE,
                                   env->riemann_cert,
                                   RIEMANN_CLIENT_OPTION_TLS_KEY_FILE,
                                   env->riemann_cert_key,
                                   RIEMANN_CLIENT_OPTION_TLS_HANDSHAKE_TIMEOUT,
                                   10000,
                                   RIEMANN_CLIENT_OPTION_NONE);
        break;
    default:
        errx(1, "inconsistent state");
    }

    if (e != 0) {
        fprintf(stderr, "could not connect to riemann host: %s\n",
                strerror(-e));
        return;
    }

    /*
     * This will free our events.
     */
    riemann_client_send_message_oneshot(env->rclient, rm);
    riemann_client_disconnect(env->rclient);
}

int
main(int argc, const char *argv[])
{
    struct rpp  env;
    time_t      tstart;
    long        duration;
    long        remaining;

    if (argc != 2) {
        usage();
        errx(1, "invalid arguments");
    }

    debug = (getenv("RPP_DEBUG") != NULL);

    bzero(&env, sizeof(env));
    parse_configuration(&env, argv[1]);

    if ((env.po = ping_construct()) == NULL) {
        err(1, "cannot allocate ping object");
    }

    env.rclient = riemann_client_new();
    if (env.rclient == NULL)
        err(1, "cannot create riemann client");
    ping_setopt(env.po, PING_OPT_TIMEOUT, &env.ping_timeout);
    ping_setopt(env.po, PING_OPT_TTL, &env.ping_ttl);

    /*
     * Our main loop.
     */
    for (;;) {
        tstart = time(NULL);

        /*
         * Add all configured hosts
         */
        rpp_add_hosts(&env);

        /*
         * Ask liboping to send out pings
         */
        if (ping_send(env.po) < 0) {
            errx(1, "cannot ping: %s", ping_get_error(env.po));
        }

        /*
         * Send results to riemann
         */
        rpp_send_messages(&env);

        /*
         * Remove hosts from object, this gives us a chance of
         * working through temporary DNS resolution errors.
         */
        rpp_remove_hosts(&env);

        duration = (time(NULL)) - tstart;
        remaining = env.interval - remaining;

        if (debug) {
            printf("took: %ld, sleeping: %ld\n", duration, env.interval - duration);
        }
        /*
         * Remove all configured hosts
         */
        if (remaining > 0)
            sleep(remaining);
    }
}
