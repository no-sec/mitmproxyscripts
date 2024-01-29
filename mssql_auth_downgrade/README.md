# mitmproxy_mssql_auth_downgrade.py

## Purpose

This [mitmproxy](https://mitmproxy.org/) script is supposed to downgrade the TDS PRELOGIN communication packages to a state where the client and server do not support encryption allowing to decode the connection information including username and password.

## Background

This script was developed based on the Metasploit script [mssql_auth_downgrade.rb](https://f0rki.at/code/mssql_auth_downgrade.rb) (see <https://www.f0rki.at/microsoft-sql-server-downgrade-attack.html>).

## Usage

Example command to run mitmproxy in [reverse TCP mode](https://docs.mitmproxy.org/stable/concepts-modes/#reverse-proxy):
```bash
mitmproxy --mode reverse:tcp://<SQLSERVERADDRESS>:1433@9000 -s mitmproxy_mssql_auth_downgrade.py
```
Whereby `SQLSERVERADDRESS` is the hostname or IP address of the actual MS SQL server. Consider changing the default SQL server port 1433 if this differs in your scenario.

After this there is a local port (`9000`) on which mitmproxy forwards all packages towards the actual server. The system or application that is supposed to connect to a MS SQL database now needs to be reconfigured to connect to mitmproxy (`localhost:9000`). This depends on the system or application itself. The command above assumes that the system or application is resided on the same system as the mitmproxy is running.

## Scenario

The script was developed for cases where a fat client connects to a MS SQL server without directly making the credentials accessible. So for example the credentials are hidden in the program code or encrypted in some files.

## Why not Metasploit?

You may wonder why not using the Metasploit module in the first place. This is due to the fact that Metasploit requires an installation and may be bloated for such a small use-case. Using mitmproxy and this script requires no further installation, administrative privileges or software.