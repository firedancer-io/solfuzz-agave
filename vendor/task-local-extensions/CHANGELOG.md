# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4] - 2023-03-09
### Changed
- Switched out task-local impl from tokio to using a custom one. Allows for wasm32 compat now

## [0.1.3] - 2022-09-06
### Changed
- The internal representation of `Extensions` no longer uses an `IdHasher` and instead uses the default hasher in order to be safe in case the representation of `TypeId` changes in future

## [0.1.2] - 2022-08-30
### Added
- `with` method for builder pattern insertion
- `append` method for combining two Extension sets

### Changed
- The internal representation of `Extensions` to be a little more sensible

## [0.1.1] - 2021-08-31
### Changed
- Renamed going forward to `task-local-extensions` from `truelayer-extensions`

## [0.1.0] - 2021-08-11
### Added
- Initial version: `Extensions`, `with_extensions`, `get_local_item` and `set_local_item`.
