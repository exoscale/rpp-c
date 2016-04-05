rpp: riemann persistent ping
============================

rpp sends regular ICMP echo messages to a provided list of hosts and
reports the results to [riemann](http://riemann.io).

### Dependencies

- `liboping`: http://noping.cc/
- `riemann-c-client`: https://github.com/algernon/riemann-c-client
- `libbsd`: https://libbsd.freedesktop.org/wiki/

All of these should be available from your favorite linux distribution.

### Building

```
make
```

### Configuration

```
## riemann options
riemann-host 127.0.0.1
riemann-port 5555
riemann-service ping
riemann-proto tcp
riemann-ca-cert /path/to/ca-crt.pem
riemann-cert /path/to/cert.pem
riemann-cert-key /path/to/cert.key.pem
riemann-tag rpp
riemann-attr akey avalue
interval 15

## hosts
host foo.example.com
host bar.example.com
```

The following options are supported:

- `riemann-proto`: Either tls, tcp, or udp.
- `riemann-host`: Riemann host.
- `riemann-port`: Riemann port.
- `riemann-ca-cert`: Path to a CA certificate file when in TLS mode.
- `riemann-cert`: Path to a certificate when in TLS mode.
- `riemann-cert-key`: Path to a certificate key when in TLS mode.
- `riemann-service`: A riemann service, defaults to *ping*.
- `riemann-tag`: Add a tag to riemann events.
- `riemann-attr`: Add a string attribute to riemann events.
- `riemann-ttl`: TTL to attach to riemann events.
- `ping-timeout`: Timeout after which pings will be considered lost.
- `ping-ttl`: TTL to attach to ICMP echo messages.
- `interval`: Interval at which to send ICMP echo messages.
- `host`: Add a host to the list of probed hosts.

The first argument for `host` is the host to ping. Additional
arguments are accepted. The first character determine the type of the
argument:

 - `:` to change the hostname that would be sent to Riemann
 - `+` to add a specific Riemann tag

### Running

Since ping requires raw sockets, rpp should be run as root.

```
rpp <configuration file>
```

If the `RPP_DEBUG` environment variable is set, produce some additional output
on stdout.
