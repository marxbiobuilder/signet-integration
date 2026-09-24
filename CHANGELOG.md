# Changelog

All notable changes to this package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- 原始碼從 `marxbiotech/ordersync-marxbio-tech` 的 `packages/signet-integration`
  搬到本 repo；`repository` 欄位隨之更新。發佈改由 tag `vX.Y.Z` 觸發 GitHub
  Actions，以 npm trusted publishing 進行。

## [0.1.1] - 2026-09-24

### Fixed

- guard 先把 principal 掛上 request 再寫 `authorized` 決策行；賦值失敗不會留下
  假的 authorized 紀錄。
- resolver `logFields` 用到保留鍵時，先寫一行 `metric=resolver_contract_error`
  再丟 500。
- options 驗證：`requestPrincipalKey` 保留鍵補齊 Express getter 欄位、不可為空；
  `scopesSupported` 與 scope vocabulary 逐項驗 scope token（RFC 6749 §3.3）；
  canonical resource 不是 URL 時報出欄位名。

## [0.1.0] - 2026-09-24

### Added

- 首次公開發佈：`SignetIntegrationModule.forRoot({ options, resolver })`、
  `SignetBearerGuard`、RFC 6750 `WWW-Authenticate` challenge、RFC 9728
  protected-resource metadata、deployment profile 配對檢查、scope vocabulary、
  `@marxbiotech/signet-integration/testing` 測試工具。

[Unreleased]: https://github.com/marxbiobuilder/signet-integration/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/marxbiobuilder/signet-integration/releases/tag/v0.1.1
[0.1.0]: https://github.com/marxbiobuilder/signet-integration/releases/tag/v0.1.0
