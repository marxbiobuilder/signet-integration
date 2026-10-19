# Changelog

All notable changes to this package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `SignetBearerVerification.verifyToken(token)`：驗證不是從 `Authorization`
  header 來的 token（例如 login flow 從 token endpoint 換到的），走同一個
  verifier、同樣的 `signet_disabled`；回傳 `VerifyResult`，不寫 log。直接呼叫
  的一方要自己記錄每個 `ok: false`（記錄前先 sanitise `reason`）；程序本身的
  缺陷仍會 throw，應成為 500。`verify(request)` 改為呼叫它，行為與 log 不變。
- `SignetBearerVerification.enabled`：Signet 通道旗標（`signetEnabled`）是否
  開啟，給拿到 token 之前就要判斷的呼叫端。
- `SignetBearerRejectionEnum`（`DISABLED`、`HEADER_MISSING`、
  `HEADER_MALFORMED`）：`SignetBearerVerification` 自己產生的拒絕原因，與
  `JwtRejectionEnum` 並列。
- Login flow（authorization code + PKCE，public client）到驗證身分為止：
  - `SignetLoginStrategy<P>(entry)`：每個 `SignetLoginEntry`（一條 redirect
    URI／環境）一個 Passport strategy 的 mixin；subclass 實作 `resolve()`，跟
    Bearer 通道同一份 `SignetPrincipalResolver` 契約。`begin(res)` 寫 state
    cookie 並回傳 authorization URL；callback 的 `validate()` 先驗 state（IdP
    的錯誤回應也一樣）、再換 code、驗 access token，最後交給
    `SignetDecision`。`P` 要明確寫出，無法推斷。
  - `SignetLoginError`／`SignetLoginFailureEnum`：login 路徑失敗一律 throw 並
    帶 reason（與 Bearer 的「回 false、統一 401」不同），由 app 在
    `AuthGuard(entry.name).handleRequest` 對應成 UI。缺 admission scope 是
    `ADMISSION_SCOPE_NOT_GRANTED`。套件自身的程式缺陷不包成
    `SignetLoginError`，照常成為 500。
  - state cookie 以 `stateSecret` 經 HKDF 衍生的金鑰加密（JWE `dir` +
    A256GCM），HttpOnly、SameSite=Lax、Path＝redirect URI 的 path、Max-Age
    600 秒，redirect URI 是 https 時加 Secure。旗標開啟時每次 callback 都在
    瀏覽器端清除；伺服器不記錄用過的 state，重放由 IdP 的一次性 code 擋下。
    `STATE_INVALID` 的 log detail 區分 `cookie_missing`／`unopenable`／
    `expired`／`malformed`／`entry`／`state`。
  - 授權請求只帶一個 `resource`（canonical resource）；discovery 的 `issuer`
    必須逐字相同，deployed 環境兩個 endpoint 都必須是 https；token 的
    `client_id` 必須是 login client。discovery 與 token endpoint 都不跟隨
    redirect，逾時各 5 秒且涵蓋讀取 body。
  - `SignetEnvNames.login`（optional，`{ clientId, stateSecret }`）：登錄了
    login strategy 時，名稱在 `onModuleInit` 檢查（不論旗標）；值只在 Signet
    旗標開啟時讀，拒絕空的或前後帶空白的 client id、不足 32 bytes 的
    secret，以及不是 http(s) URL 的 issuer（否則每次登入都會被歸成
    transport 失敗）。
  - entry 在建立 class 時驗證並凍結成副本（名稱、scope token、每個環境的
    redirect URI）；`onModuleInit` 時再對照 options 的 deployed 環境，缺少或
    多出都會失敗。subclass 覆寫 `onModuleInit` 而沒呼叫 super 時，flow 會在
    第一次登入時建立。
  - `SignetBearerVerification.issuer`：設定的 issuer（旗標關閉時為 `null`），
    login flow 的 discovery 用它，設定只讀一次。
  - testing：`startTestAuthorizationServer({ clientId })`，含
    `overrideDiscovery()`、`scriptTokenEndpoint()`（含 raw body、redirect、
    body 卡住；腳本形狀互斥）、`sign()`、`discoveryRequests()`、`reset()`。
    server 自身出錯時中斷連線並記入 `failures()`，`close()` 會 reject，
    不會偽裝成 issuer 的 500。

### Changed

- `challengeFor`／`BearerChallengeFilter`：`SignetLoginError` 不加
  `WWW-Authenticate`——瀏覽器登入失敗不是 Bearer 請求。

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
