# Changelog

Notable changes to the library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2025-09-04

### Fixed

- Handle timezones correctly when passing timestamps from Zino to Argus.
- Properly follow up on state changes in all Argus incidents created by this
  glue service.

## [0.2.0] - 2025-07-25

### Added

- Configuration option to sync Argus acknowledgements back to Zino cases as an
  administrative state change (either `working` or `waiting` state)

- Configuration option to sync Argus ticket URL changes back to Zino case
  history.

## [0.1.0] - 2025-04-04

First public release.
