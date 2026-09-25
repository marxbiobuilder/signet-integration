# Changelog

All notable changes to this package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-25

Passport 優先的分層：resolver 可以直接寫在你自己的 Passport strategy 裡，
principal 由 Passport 掛到 `request.user`；套件提供 helper 讓 401／403／503／500
分類與決策 log 在兩條路徑上完全一致。既有的 `forRoot` 路徑行為不變。

### Added

- `SignetPrincipalStrategy<P>`：抽象 strategy，subclass 實作 `resolve()`
  （Passport verify callback 的形狀，身分已驗證），套件相依以 property injection
  注入，建構子留給你。
- `SignetPassportGuard`：`AuthGuard('signet-jwt')` 加 `@Public()` 與統一 401；
  `SignetBearerGuard` 改為它的 subclass。
- `SignetDecision`：admission scope、resolver 呼叫、結果分類、決策 log 的單一
  實作；guard 與 strategy 都經過它。resolver 是參數而不是先呼叫，呼叫端沒有
  地方能把 store 錯誤吞成 401。
- `SignetIntegrationModule.forPassport({ options })`：不含 resolver 與 guard
  的接線，給自帶 strategy 的 consumer。
- `SignetBearerVerification`：strategy 共用的驗證步驟（讀設定、建 verifier、
  拒絕時的 log），供自組 strategy 使用。
- `@marxbiotech/signet-integration/passport` 子入口：主入口去掉 metadata
  controller，不載入 `@nestjs/swagger` 與 `@nestjs/throttler`。

### Changed

- `@nestjs/swagger`、`@nestjs/throttler` 改為 optional peer；只有
  `createProtectedResourceController` 需要。
- `SignetBearerGuard` 建構子參數改為 `(resolver, SignetDecision, options,
  Reflector)`；沒有自己建構子的 subclass（OrderSync）不受影響。


## [0.1.2] - 2026-09-24

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

[Unreleased]: https://github.com/marxbiobuilder/signet-integration/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/marxbiobuilder/signet-integration/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/marxbiobuilder/signet-integration/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/marxbiobuilder/signet-integration/releases/tag/v0.1.1
[0.1.0]: https://github.com/marxbiobuilder/signet-integration/releases/tag/v0.1.0
