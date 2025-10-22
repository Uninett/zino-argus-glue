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

## Developing Zino-Argus-Glue

### Using towncrier to automatically produce the changelog
#### Before merging a pull request
To be able to automatically produce the changelog for a release one file for each
pull request (also called news fragment) needs to be added to the folder
`changelog.d/`.

The name of the file consists of three parts separated by a period:
1. The identifier: the issue number
or the pull request number. If we don't want to add a link to the resulting changelog
entry then a `+` followed by a unique short description.
2. The type of the change: we use `security`, `removed`, `deprecated`, `added`,
`changed` and `fixed`.
3. The file suffix, e.g. `.md`, towncrier does not care which suffix a fragment has.

So an example for a file name related to an issue/pull request would be `214.added.md`
or for a file without corresponding issue `+fixed-pagination-bug.fixed.md`.

This file can either be created manually with a file name as specified above and the
changelog text as content or one can use towncrier to create such a file as following:

```console
$ towncrier create -c "Changelog content" 214.added.md
```

When opening a pull request there will be a check to make sure that a news fragment is
added and it will fail if it is missing.

#### Before a release
To add all content from the `changelog.d/` folder to the changelog file simply run
```console
$ towncrier build --version {version}
```
This will also delete all files in `changelog.d/`.

To preview what the addition to the changelog file would look like add the flag
`--draft`. This will not delete any files or change `CHANGELOG.md`. It will only output
the preview in the terminal.

A few other helpful flags:
- `date DATE` - set the date of the release, default is today
- `keep` - do not delete the files in `changelog.d/`

More information about [towncrier](https://towncrier.readthedocs.io).