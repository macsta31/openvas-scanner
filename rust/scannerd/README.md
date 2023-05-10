# scannerd

Is the implementation for [scanner-api](https://greenbone.github.io/scanner-api/).

# Configuration

scannerd is configured via environment variables.

| Name | Default | Description |
| -- | -- | -- |
| RUST_LOG | Off | Sets the log value, per default it is disabled. Possible log levels are: trace, debug, info, warn, error |
|OSPD_SOCKET | /run/ospd/ospd-openvas.sock | The unix socket address of ospd-openvas. |

# TODO

There are still a lot of things open to do:
- add correct error responses
- verify Content-Type
- remove code duplications
- write better tests
- document the code
- create tests with ospd backend

