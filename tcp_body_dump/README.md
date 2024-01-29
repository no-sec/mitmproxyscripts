# mitmproxy_tcp_body_dump.py

## Purpose

This [mitmproxy](https://mitmproxy.org/) script is supposed to store tcp packages base64-encoded in a file to than further analyze with for example [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)).

## Background

mitmproxy in its console version do not allow to easily see observes TCP traffic. The web UI helps a bit with different decodings but is still limited.

## Usage

Example command to run mitmproxy in [reverse TCP mode](https://docs.mitmproxy.org/stable/concepts-modes/#reverse-proxy):
```bash
mitmproxy --mode reverse:tcp://<SERVERADDRESS>:7878@9000 -s mitmproxy_tcp_body_dump.py
```
Whereby `SERVERADDRESS` is the hostname or IP address of the server.

After this there is a local port (`9000`) on which mitmproxy forwards all packages towards the actual server. The system or application that is supposed to connect to a server now needs to be reconfigured to connect to mitmproxy (`localhost:9000`). This depends on the system or application itself. The command above assumes that the system or application is resided on the same system as the mitmproxy is running.

The files generated (`tcp_body_dump_*`) contain a timestamp within the filename to be more precise, which is the relevant one. For each TCP package a new line is written, while it is prepended with `c;` if the client was sending this package or `s;` if the server responded with this package. The TCP packages are base64-encoded.