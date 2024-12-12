# mitmproxy_add_kerberos_auth.py

## Purpose

This [mitmproxy](https://mitmproxy.org/) script is supposed to add kerberos authentication to the request in a setup where we are testing web applications that use kerberos authentication and native Kerberos authentication cannot be used easily.

## Usage

Example command:
```bash
mitmproxy -s add_kerberos_auth.py
```

After this there is a local port (`8080` per default) on which mitmproxy forwards all packages towards the actual server. As this script is purposed for web applications using Kerberos, Burp will be in usage. Therefore, mitmproxy can there be configured as an Upstream Proxy. On the system running mitmproxy itself, a Kerberos ticket can be acquired via kinit.

## Scenario

The script was developed for pentesting web applications using Kerberos authentication, where we have a testsetup in which it is not possible for the Browser to use native Kerberos authentication (i.e. we do not have a Domain-joined system).
