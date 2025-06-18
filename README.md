# Zino ↔ Argus glue service

This is a [glue
service](https://argus-server.readthedocs.io/en/latest/integrations/glue-services/index.html)
for integration between [Argus](https://github.com/Uninett/Argus), the alert
aggregation server, and [Zino](https://github.com/Uninett/zino), the network
state monitor provided by Sikt.

This is still a work in progress and more information will be added here later.

## Installing zino-argus-glue

### From Python Package Index (PyPI)

```console
$ pip install zino-argus-glue
...
$ zinoargus --help
usage: zinoargus [-h] [-v] [-c CONFIG_FILE]

options:
  -h, --help            show this help message and exit
  -v, --verbose
  -c CONFIG_FILE, --config-file CONFIG_FILE
$
```

### From source (this repository)

```console
$ pip install .
...
$ zinoargus --help
usage: zinoargus [-h] [-v] [-c CONFIG_FILE]

options:
  -h, --help            show this help message and exit
  -v, --verbose
  -c CONFIG_FILE, --config-file CONFIG_FILE
$
```

## Configuring zino-argus-glue

The `zino-argus-glue` program needs to know how to connect to both a Zino API
server and an Argus API server in order to synchronize incidents from Zino to
Argus.  Addresses and authentication tokens for these APIs are configured in
`zinoargus.toml`.  `zinoargus` reads this file the current working directory,
or you can specify an alternate path to a configuration file using the `-c`
command line option.  See [zinoargus.toml.example](./zinoargus.toml.example)
for an example configuration file.

## Copying

Copyright 2025 Sikt (The Norwegian Agency for Shared Services in Education and
Research)

Licensed under the Apache License, Version 2.0; See [LICENSE](./LICENSE) for a
full copy of the License.
