# Xignet Core 與 Payload v3 實作計畫

歸檔日期：2026-11-12。狀態：架構方向已確認；API 為草案，尚未實作或發布。

本計畫採用方案 A：Payload 直接整合 Xignet，使用共用 SDK 重用 JWT、OIDC 與 MCP 認證邏輯，不新增 Nest gateway。第一個接入專案為 `marxbiotech/www-marxbiotech-com`，維持 Payload v3，依序交付唯讀 MCP、後台 SSO、受控內容寫入。

## 文件分工與基底

- 本文件擁有共用套件 API、實作階段、相容性與發布契約。
- 官網的身分綁定、資料權限、部署與驗收，歸入 `www-marxbiotech-com` 的 `docs/architecture/xignet-payload-v3-integration-plan.md`。
- [官網接入計畫歸檔分支](https://github.com/marxbiotech/www-marxbiotech-com/blob/docs/xignet-payload-v3-plan-20261112/docs/architecture/xignet-payload-v3-integration-plan.md)。該文件於官網合併前以文件分支為準。
- 本次歸檔基於 `signet-integration` 最新 main `c4b4ec87df77266cb5d96c373e70ad2216544aea`；後續實作亦須從當時最新 main 建立分支。
- 官網基底為 main `6120fa58241de17f2b025eefe7035a2ef9a64f08`，第一個實體採已有的 `bulletins`。`news`、草稿發布與自動重建 hook 仍屬官網功能分支，不能視為 main 現況。

## 套件邊界

```text
packages/core       @xignet/core       新增
packages/payload    @xignet/payload    新增
packages/nest       @xignet/nest       逐步改用 core，保留公開 API
packages/client     @xignet/client     維持 outbound client_credentials 用途
```

| 層級 | 責任 | 由使用端決定 |
|---|---|---|
| core | JWT/JWKS、identity、scope、OIDC/PKCE、OAuth metadata/challenge | 本地使用者、角色、資料權限 |
| payload | MCP adapter、user resolver、Next routes、原生 session、access 組合 | collection、發布語意、綁定儲存方式 |
| 接入專案 | resolver、綁定、角色、資料與操作政策、環境設定 | — |

core 不依賴 Nest、Express、Payload 或資料庫。首版支援 Node.js server，不承諾 Edge Runtime。`@xignet/core` 與 AS 內部的 `@xignet-marxbio-tech/core` 是不同套件。各 CMS 維持自己的 Payload secret、session 與使用者資料；各專案／環境使用各自的 resource audience 與 web client。

## Core API 草案

入口規劃：`@xignet/core`、`@xignet/core/oidc`、`@xignet/core/oauth`。以下型別是公開契約草案，不是可直接安裝使用的 API。

```ts
interface VerifiedIdentity {
  readonly issuer: string
  readonly subject: string
  readonly clientId: string
  readonly scopes: readonly string[]
  readonly expiresAt: number // Unix seconds
  readonly claims: Readonly<Record<string, unknown>>
}

type VerificationResult =
  | { ok: true; identity: VerifiedIdentity }
  | {
      ok: false
      kind: 'invalid_token' | 'verification_unavailable'
      reason: string
    }

interface TokenVerifier {
  verifyAccessToken(token: string): Promise<VerificationResult>
}

function createTokenVerifier(options: {
  issuer: string
  audience: string
  jwksUri: string
  clockToleranceSeconds?: number
}): TokenVerifier

function hasAllScopes(
  identity: VerifiedIdentity,
  required: readonly string[],
): boolean
```

驗證契約：

- 檢查簽章、非對稱演算法 allowlist、issuer、audience、有效期與必要 claims。
- verifier 為 process 共用實例，保留 JWKS cache、輪替與 timeout 控制。
- identity 不包含本地 role 或 Payload user ID；以 `(issuer, subject)` 綁定本地身分。
- 保留既有 scope/scp 與 deployment profile 行為；抽取與行為調整分開驗收。
- invalid token、JWKS 暫時不可用與程式缺陷分開處理；reason 只供整理後的內部紀錄，不洩漏原始 credential。
- 新 core 的錯誤分類由 Nest compatibility wrapper 映回既有對外契約，避免抽取時改變既有 consumer 行為。

OIDC 採資料介面，由 adapter 處理 HTTP：

```ts
interface OidcClient {
  begin(): Promise<{
    authorizationUrl: string
    transaction: LoginTransaction
  }>

  complete(input: {
    callbackUrl: string
    transaction: LoginTransaction
  }): Promise<{
    identity: VerifiedIdentity
    idTokenClaims: Readonly<Record<string, unknown>>
  }>
}
```

`LoginTransaction` 是 server-only 資料，包含 state、PKCE verifier 與期限。adapter 加密封裝為短效 HttpOnly cookie，core 驗證 state 與協定結果；完成或失敗後 adapter 清除 transaction cookie。首次沿用現有 public client＋PKCE 流程，驗證 access token、ID token、client 綁定及一致的 subject。nonce 等協定擴充另立工作項目，避免與既有 Nest 重構混在一起。

OIDC client 的 factory 設定需涵蓋固定 issuer、clientId、redirectUri、resource、scopes、timeout；discovery 僅由信任設定驅動。core 不接受由未驗證 token 指定的 issuer/JWKS。callback 的 tokens 不交由業務程式保存；browser SSO 首版不要求 offline refresh token。

OAuth helpers 提供 RFC 9728 metadata 與 RFC 6750 challenge 的資料／header 組裝，不依賴 web framework。固定 resource URL，不依不可信 Host header 動態推導。

## Payload API 草案

入口：`@xignet/payload/v3` 與 `@xignet/payload/next`。未來 v4 使用獨立 adapter，core 共用。

```ts
type UserResolution<TUser> =
  | { status: 'allowed'; user: TUser }
  | {
      status: 'denied'
      reason: 'unbound' | 'disabled' | 'not_allowed'
    }

type ResolveUser<TUser> = (input: {
  identity: VerifiedIdentity
  channel: 'login' | 'mcp'
  payload: Payload
  login?: { idTokenClaims: Readonly<Record<string, unknown>> }
}) => Promise<UserResolution<TUser>>
```

`Payload` 為 Payload SDK 型別；user 必須符合設定的 auth collection。套件不寫死 `users`、admin/editor 或 email 查詢策略。resolver 的資料庫故障不可偽裝為未綁定身分。

```ts
const xignet = createXignetPayload({
  issuer,
  jwksUri,
  resource,
  admissionScopes: ['cms:access'],
  userCollection: 'users',
  resolveUser,
  mcp: {
    enabled: true,
    collections: {
      bulletins: { find: { scopes: ['cms:read'] } },
    },
    globals: {},
  },
  login: {
    enabled: true,
    clientId,
    redirectUri,
    scopes: ['openid', 'email', 'cms:access'],
    transactionSecret,
    successRedirect: '/admin',
    session: {
      maxAgeSeconds: 7200,
      absoluteMaxAgeSeconds: 7200,
    },
  },
})

// Payload buildConfig 的 plugins 加入 xignet.plugin()
// Next.js routes 分別匯出 handlers.login / callback / metadata
const handlers = createXignetRouteHandlers(xignet)
```

上例以官網作為使用示例；scope 字串、collection slug 與 session 期限均為設定，不是 core 常數。唯讀 MCP 階段將 login.enabled 設為 false；SSO 驗收後才啟用。

| 接點 | 責任 |
|---|---|
| `xignet.plugin()` | 組合官方 MCP plugin、overrideAuth、access/hook 與必要 session adapter |
| `/api/mcp` | 驗證 Xignet bearer，映射本地 user，交由官方 MCP 執行 |
| `/auth/xignet/login` | 建立 OIDC transaction，設定 cookie，redirect |
| `/auth/xignet/callback` | 驗證 callback、解析 user、建立原生 Payload session |
| `/.well-known/oauth-protected-resource/api/mcp` | 提供該 resource 的 metadata |

使用端只安裝一次 MCP integration。官方 plugin 的版本與公開 exports 需在 phase 0 驗證；不承諾可直接使用未公開的內部 import。

## MCP 與 Session 的邊界

- MCP bearer 僅由 MCP adapter 接受，不全域註冊成可呼叫 refresh/login 的認證策略。
- 無效 Xignet token 不回退至 API key、browser cookie 或管理員身分。
- 每次 MCP HTTP 請求驗證 token、admission scopes 與本地 user；MCP session ID 不作認證憑證。
- 將已驗證 identity 放在伺服器控制的 request context，保留 issuer、subject、clientId、scopes；不同使用者／請求不得共用狀態。
- browser SSO 建立原生 Payload session，包含 SID、cookie、refresh、logout、必要 hooks；不能僅手工簽 JWT 就宣告完成。
- phase 0 證明 refresh 不突破 absoluteMaxAge，停用可撤銷 session；儲存絕對期限／登入來源的具體方式依 v3 擴充接點決定。
- Xignet 登出／撤銷 refresh grant 不等於自動撤銷 Payload session；首版採短效、絕對期限與本地撤銷。即時跨系統登出不列為現成功能。
- callback 固定同 origin redirect，cookie 使用適當 Secure/HttpOnly/SameSite/Path；驗證 state、PKCE、重放與錯誤 callback。
- 不記錄 token、authorization code、cookie 或原始 transaction。稽核記錄身分、client、操作、目標、結果與 correlation ID。

## 授權組合與 Mutation Policy

實際權限為「專案開放操作 ∩ token scopes ∩ Payload 本地資料／欄位權限」。未列出的 collection、global、custom tool 預設關閉；實驗性 auth、schema、config、jobs 操作不開放。

工具可見性與執行時檢查使用同一份 policy。組合既有 Access 時保留 boolean/Where 語意，以 AND 交集而非覆蓋文件條件。Local API 必須傳入真實 user、request 並指定 `overrideAccess: false`。MCP 缺少可信 context 必須拒絕；一般 REST/GraphQL 與 browser session 維持原本規則。

後續寫入草案：

```ts
bulletins: {
  find: { scopes: ['cms:read'] },
  create: { scopes: ['cms:write'] },
  update: { scopes: ['cms:write'] },
  mutationPolicy: websiteBulletinMutationPolicy,
}
```

mutationPolicy 接收操作、原文件、輸入資料與草稿模式，回傳額外 scopes 或拒絕原因。於實際修改前執行，批次操作逐份檢查；不得只透過隱藏工具實現限制。具體 callback TypeScript 型別在 phase 0/4 依 hook 能取得的資訊定案。

發布語意屬使用端：無草稿的公開內容，create/update 可直接影響公開 API，須額外要求 publish scope；有草稿的專案需區分另存草稿、更新公開版本、發布、下架與公開 global。刪除首版關閉。

## 實作階段與交付條件

| 階段 | 交付 | 完成條件 |
|---|---|---|
| 0 相容性驗證 | 最小 Payload fixture、MCP/Next route 與 native session spike | challenge headers、overrideAuth、真實 user、refresh/logout 與絕對期限具可重現測試 |
| 1 Core 抽取 | JWT/identity/scopes/OAuth helpers；Nest compatibility wrapper | 原公開 API、scope/profile 與拒絕行為相容；原測試通過 |
| 2 唯讀 MCP | Payload adapter、metadata、resolver、access 組合 | 官網 staging 以 Xignet token 讀取 bulletins；scope/角色/context 隔離驗證通過 |
| 3 SSO | 共用 OIDC flow、Next routes、原生 session、登入 UI 接點 | Admin 登入、refresh、logout、停用撤銷與 callback 失敗行為完整 |
| 4 受控寫入 | mutationPolicy、操作紀錄與明確公開內容規則 | read token 不能寫；write token 不能改公開內容；批次／欄位／多語系不能繞過 |
| 5 發布與重用 | 獨立版本、workflow、README、fixture、相容性矩陣 | 官網驗收；第二個 CMS 僅替換 config/resolver/policy 可接入 |

工作可以分 PR，但每個 PR 由當時最新 main 開始；有依賴的階段待前置合併後再同步基底。第一個可交付里程碑是 core/payload 預覽版與官網 staging 唯讀 MCP。

## 相容性與套件發布

- 官網目前 lockfile 為 Payload 3.77.0；先用 Payload 3.93.0 及配套版本建立測試基線，不宣告全 v3 支援。
- 升級官網 Payload 與加入認證分成可獨立審查的變更；升級驗收失敗先修正基線。
- Payload 與官方 MCP 使用 peer dependencies／明確相容性表，避免重複 framework instance；core 與既有 Nest 的 jose 相容性須一起確認。
- 保留 Nest 的 CommonJS/ESM consumer 相容性，透過實際 npm pack 安裝測試驗證；Next standalone build 也須測試。
- core、payload 分別版本化，新增 `core-vX.Y.Z`、`payload-vX.Y.Z` 與對應 trusted publishing workflows，先發 0.x 預覽版。
- 發布 core 後，再發布依賴它的 Nest/Payload；發布設定不得把 workspace-only 版本帶進 npm。
- 第二個 Payload 專案接入前不凍結 1.0；未來 v4 adapter 共用 core，但不假設 v3 session/MCP 接點可直接沿用。

## 驗收矩陣

- [ ] 錯 issuer/audience、過期、缺必要 claim、壞簽章與錯誤 scope 格式拒絕。
- [ ] JWKS 輪替、timeout 與 unavailable 可辨識且不放行。
- [ ] OIDC state、PKCE、重放、ID token 與 access token subject/client 綁定通過正反向測試。
- [ ] 未綁定、停用、權限變更與 resolver 故障有明確結果。
- [ ] 工具枚舉／直接呼叫／resource 讀取皆不能繞過 policy，request context 不跨 user 洩漏。
- [ ] Payload Where 與 field access 保留，Local API 不使用管理員 bypass。
- [ ] cookie、native SID、refresh 絕對期限、logout 與撤銷測試通過。
- [ ] 一般公開 API、既有 API key 使用與前台 SSG 不受 MCP 規則誤傷。
- [ ] 打包後 Nest consumer、Next build、peer dependency matrix 驗證通過。

## 參考來源

- [既有套件結構](../../README.md)
- [既有 JWT verifier](../../packages/nest/src/jwt-verifier.ts)
- [既有 OIDC flow](../../packages/nest/src/login-flow.ts)
- [Payload v3.93 MCP overrideAuth](https://github.com/payloadcms/payload/blob/v3.93.0/packages/plugin-mcp/src/endpoints/resolveAccessSettings.ts)
- [Payload v3.93 MCP types](https://github.com/payloadcms/payload/blob/v3.93.0/packages/plugin-mcp/src/types.ts)
- [Payload custom strategies](https://payloadcms.com/docs/authentication/custom-strategies)
