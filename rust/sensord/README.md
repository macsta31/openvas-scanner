# scannerd

Is the implementation for [scanner-api](https://greenbone.github.io/scanner-api/).

# Usage

```
Usage: sensord [OPTIONS]

Options:
  -c, --config <config>
          path to toml config file [env: SENSORD_CONFIG=]
      --feed-path <feed-path>
          path to openvas feed [env: FEEED_PATH=]
      --feed-check-interval <SECONDS>
          interval to check for feed updates in seconds [env: FEED_CHECK_INTERVAL=]
      --tls-certs <tls-certs>
          path to server tls certs [env: TLS_CERTS=]
      --tls-key <tls-key>
          path to server tls key [env: TLS_KEY=]
      --tls-client-certs <tls-client-certs>
          path to client tls certs. Enables mtls. [env: TLS_CLIENT_CERTS=]
      --enable-get-scans
          enable get scans endpoint [env: ENABLE_GET_SCANS=]
      --ospd-socket <ospd-socket>
          socket to ospd [env: OSPD_SOCKET=]
      --result-check-interval <SECONDS>
          interval to check for new results in seconds [env: RESULT_CHECK_INTERVAL=]
  -l, --listening <IP:PORT>
          the address to listen to (e.g. 127.0.0.1:3000 or 0.0.0.0:3000). [env: LISTENING=]
  -h, --help
          Print help
```

## Defaults

The default lookup path for the configs are:
- `/etc/sensord/sensord.toml`
- `$HOME/.config/sensord/sensord.toml`


```
[feed]
path = "/var/lib/openvas/plugins2"

[feed.check_interval]
secs = 3600
nanos = 0

[endpoints]
enable_get_scans = false

[tls]
certs = "/etc/sensord/tls/certs.pem"
key = "/etc/sensord/tls/key.pem"
client_certs = "/etc/sensord/tls/clients"

[ospd]
socket = "/var/run/ospd/ospd.sock"

[ospd.result_check_interval]
secs = 1
nanos = 0

[listener]
address = "127.0.0.1:3000"
```
