import { type Logger } from '@nestjs/common';
import { type ConfigService } from '@nestjs/config';
import { type Request, type Response as ExpressResponse } from 'express';

import { readSignetAuthConfig } from './config';
import { type SignetDeploymentProfileService } from './deployment-profile';
import { type VerifiedSignetIdentity } from './jwt-verifier';
import { REFUSAL_ROUTE_MAX, sanitiseLogToken, truncate } from './log-sanitise';
import {
  LoginDiscovery,
  LoginDiscoveryError,
  transportFailure,
} from './login-discovery';
import {
  type LoginRedirectUri,
  loginRedirectUri,
  type SignetLoginEntry,
} from './login-entry';
import {
  SignetLoginError,
  type SignetLoginFailure,
  SignetLoginFailureEnum,
} from './login-error';
import {
  codeChallenge,
  LOGIN_STATE_TTL_S,
  type LoginState,
  loginStateCookie,
  loginStateCookieName,
  loginStateKey,
  newLoginState,
  openLoginState,
  readCookie,
  sealLoginState,
} from './login-state';
import {
  DEVELOPMENT_ENVIRONMENT,
  type SignetIntegrationOptions,
} from './options';
import { SignetBearerVerification } from './strategy';

export interface LoginFlowTimeouts {
  readonly discoveryMs: number;
  readonly tokenMs: number;
}

export const LOGIN_FLOW_TIMEOUTS: LoginFlowTimeouts = {
  discoveryMs: 5_000,
  tokenMs: 5_000,
};

// The longest `detail=` a rejection line carries; an IdP's `error` comes
// from the query string.
const DETAIL_MAX = 100;

// What an enabled flow holds, read once. Absent when the flag is off.
interface LoginSettings {
  readonly clientId: string;
  readonly discovery: LoginDiscovery;
  readonly key: Uint8Array;
}

// The authorization-code + PKCE flow for one entry, as a public client:
// begin() starts it, complete() turns the IdP's redirect back into a verified
// identity. What happens to that identity -- admission, the consumer's
// resolver -- is SignetDecision's, run by the strategy.
//
// The identity comes from the ACCESS token, verified by the same
// SignetBearerVerification the Bearer channel uses: the claims a resolver
// reads are the resource-server contract's either way. No ID token, no
// nonce, no refresh token is kept.
//
// Every refusal throws SignetLoginError through reject(), which writes the
// one rejection line. Nothing derived from the token, the code or the state
// is logged, and the route is the path alone: the callback's query carries
// the code.
export class SignetLoginFlow {
  private readonly verification: SignetBearerVerification;
  private readonly settings: LoginSettings | null;
  private readonly cookieName: string;
  private readonly redirectUri: LoginRedirectUri;
  private readonly canonicalResource: string;

  constructor(
    private readonly entry: SignetLoginEntry,
    configService: ConfigService,
    profiles: SignetDeploymentProfileService,
    private readonly options: SignetIntegrationOptions,
    private readonly logger: Logger,
    private readonly timeouts: LoginFlowTimeouts = LOGIN_FLOW_TIMEOUTS,
  ) {
    const { profile } = profiles;
    const development = profile.environment === DEVELOPMENT_ENVIRONMENT;
    // Checked with the flag off too: the URIs are code, and a typo should
    // not wait for the day the flag is turned on.
    this.redirectUri = loginRedirectUri(entry, profile.environment);
    this.cookieName = loginStateCookieName(entry.name);
    this.canonicalResource = profile.canonicalResource;
    this.verification = new SignetBearerVerification(
      configService,
      profiles,
      options,
      logger,
    );
    const config = readSignetAuthConfig(options, configService, profile);
    if (!config.signetEnabled) {
      this.settings = null;
      return;
    }
    const { loginClientId, loginStateSecret } = options.env;
    if (loginClientId === undefined || loginStateSecret === undefined) {
      throw new Error(
        `SignetLoginStrategy ${entry.name} needs options.env.loginClientId and options.env.loginStateSecret`,
      );
    }
    const clientId = configService.getOrThrow<string>(loginClientId);
    let key: Uint8Array;
    try {
      key = loginStateKey(configService.getOrThrow<string>(loginStateSecret));
    } catch (error) {
      throw new Error(
        `${loginStateSecret}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    this.settings = {
      clientId,
      discovery: new LoginDiscovery(
        config.jwt.issuer,
        !development,
        timeouts.discoveryMs,
      ),
      key,
    };
  }

  // Writes the state cookie on `response` and returns the authorization URL
  // to redirect to. Not a Passport step: passport-custom's validate cannot
  // redirect, so the consumer's handler does.
  async begin(response: ExpressResponse): Promise<string> {
    const request = response.req;
    const settings = this.enabled(request);
    const { authorizationEndpoint } = await this.endpoints(settings, request);
    const state = newLoginState(this.entry.name);
    response.append(
      'Set-Cookie',
      loginStateCookie(
        this.cookieName,
        await sealLoginState(settings.key, state),
        this.redirectUri.url,
        LOGIN_STATE_TTL_S,
      ),
    );
    const url = new URL(authorizationEndpoint);
    const scopes = new Set([
      ...(this.entry.scopes ?? ['openid']),
      this.options.admissionScope,
    ]);
    for (const [name, value] of [
      ['response_type', 'code'],
      ['client_id', settings.clientId],
      ['redirect_uri', this.redirectUri.value],
      ['scope', [...scopes].join(' ')],
      // RFC 8707: exactly one, the canonical resource, so the token's `aud`
      // is what the verifier expects. Signet refuses more than one.
      ['resource', this.canonicalResource],
      ['code_challenge', codeChallenge(state.verifier)],
      ['code_challenge_method', 'S256'],
      ['state', state.state],
    ] as const) {
      url.searchParams.set(name, value);
    }
    return url.toString();
  }

  // The callback: the IdP's answer, checked against the state cookie, the
  // code exchanged, the token verified.
  async complete(request: Request): Promise<VerifiedSignetIdentity> {
    const settings = this.enabled(request);
    // Read, then cleared before anything else can fail: a state is good
    // for one callback, whatever that callback's outcome.
    const sealed = readCookie(request.headers.cookie, this.cookieName);
    this.clearStateCookie(request);

    const error = queryValue(request, 'error');
    if (error !== undefined) {
      throw this.reject(
        request,
        error === 'access_denied'
          ? SignetLoginFailureEnum.CANCELLED
          : SignetLoginFailureEnum.IDP_ERROR,
        error,
      );
    }
    const state = await this.matchState(
      settings,
      sealed,
      queryValue(request, 'state'),
    );
    if (typeof state === 'string') {
      throw this.reject(request, SignetLoginFailureEnum.STATE_INVALID, state);
    }
    const code = queryValue(request, 'code');
    if (code === undefined || code === '') {
      throw this.reject(
        request,
        SignetLoginFailureEnum.IDP_ERROR,
        'code_missing',
      );
    }

    const { tokenEndpoint } = await this.endpoints(settings, request);
    const accessToken = await this.exchange(
      settings,
      request,
      tokenEndpoint,
      code,
      state.verifier,
    );
    const result = await this.verification.verifyToken(accessToken);
    if (!result.ok) {
      throw this.reject(
        request,
        SignetLoginFailureEnum.TOKEN_REJECTED,
        result.reason,
      );
    }
    // The token came straight from the token endpoint for this client's
    // code, so this cannot fail unless the issuer misbehaves; it is cheap.
    if (result.identity.clientId !== settings.clientId) {
      throw this.reject(
        request,
        SignetLoginFailureEnum.TOKEN_REJECTED,
        'client_id_mismatch',
      );
    }
    // Checked here rather than left to SignetDecision, whose 403 tells an
    // API client to re-authorise: in a login the package chose the scopes,
    // so their absence is the user's consent or the client's policy.
    if (!result.identity.scopes.includes(this.options.admissionScope)) {
      throw this.reject(
        request,
        SignetLoginFailureEnum.ADMISSION_SCOPE_NOT_GRANTED,
        'none',
      );
    }
    return result.identity;
  }

  private enabled(request: Request | undefined): LoginSettings {
    if (this.settings === null) {
      throw this.reject(request, SignetLoginFailureEnum.DISABLED, 'none');
    }
    return this.settings;
  }

  private async endpoints(
    settings: LoginSettings,
    request: Request | undefined,
  ) {
    try {
      return await settings.discovery.endpoints();
    } catch (error) {
      throw this.reject(
        request,
        SignetLoginFailureEnum.DISCOVERY_FAILED,
        error instanceof LoginDiscoveryError
          ? error.detail
          : transportFailure(error),
      );
    }
  }

  // The state this callback answers, or which check failed (for the log
  // line): no cookie this process sealed in the last ten minutes, none for
  // this entry, none whose state is the query's. A stale cookie on a wider
  // path can arrive beside the current one, so every value is tried.
  private async matchState(
    settings: LoginSettings,
    sealed: readonly string[],
    queryState: string | undefined,
  ): Promise<LoginState | 'cookie' | 'entry' | 'state'> {
    const opened: LoginState[] = [];
    for (const value of sealed) {
      const state = await openLoginState(settings.key, value);
      if (state !== null) opened.push(state);
    }
    if (opened.length === 0) return 'cookie';
    const forEntry = opened.filter(({ entry }) => entry === this.entry.name);
    if (forEntry.length === 0) return 'entry';
    return forEntry.find(({ state }) => state === queryState) ?? 'state';
  }

  private clearStateCookie(request: Request): void {
    if (request.res === undefined) {
      throw new Error(
        `SignetLoginStrategy ${this.entry.name}: the request has no response to clear the state cookie on`,
      );
    }
    request.res.append(
      'Set-Cookie',
      loginStateCookie(this.cookieName, '', this.redirectUri.url, 0),
    );
  }

  private async exchange(
    settings: LoginSettings,
    request: Request,
    tokenEndpoint: string,
    code: string,
    verifier: string,
  ): Promise<string> {
    const fail = (detail: string) =>
      this.reject(
        request,
        SignetLoginFailureEnum.TOKEN_EXCHANGE_FAILED,
        detail,
      );
    let response: Response;
    let body: unknown;
    try {
      response = await fetch(tokenEndpoint, {
        body: new URLSearchParams({
          client_id: settings.clientId,
          code,
          code_verifier: verifier,
          grant_type: 'authorization_code',
          redirect_uri: this.redirectUri.value,
        }),
        headers: {
          accept: 'application/json',
          'content-type': 'application/x-www-form-urlencoded',
        },
        method: 'POST',
        redirect: 'error',
        signal: AbortSignal.timeout(this.timeouts.tokenMs),
      });
      // Read as text inside the try: the timeout covers the body too, and a
      // body that stalls is a transport failure, not a missing token.
      const text = await response.text();
      try {
        body = JSON.parse(text) as unknown;
      } catch {
        body = undefined;
      }
    } catch (error) {
      throw fail(transportFailure(error));
    }
    const fields = (body ?? {}) as Record<string, unknown>;
    if (!response.ok) {
      // The status and the OAuth `error` code only: the body can echo the
      // code or carry a description written for humans.
      const oauthError =
        typeof fields.error === 'string' ? fields.error : 'none';
      throw fail(`status_${response.status}:${oauthError}`);
    }
    if (typeof fields.access_token !== 'string' || fields.access_token === '') {
      throw fail('access_token_missing');
    }
    return fields.access_token;
  }

  private reject(
    request: Request | undefined,
    reason: SignetLoginFailure,
    detail: string,
  ): SignetLoginError {
    this.logger.warn(
      `signet login rejected: metric=signet_login_rejected reason=${reason} detail=${sanitiseLogToken(truncate(detail, DETAIL_MAX))} entry=${this.entry.name} source=${sanitiseLogToken(request?.ip ?? 'none')} route=${sanitiseLogToken(truncate(request?.path ?? 'none', REFUSAL_ROUTE_MAX))}`,
    );
    return new SignetLoginError(reason);
  }
}

// A query parameter given exactly once; repeated or nested is absent.
function queryValue(request: Request, name: string): string | undefined {
  const value: unknown = (request.query as Record<string, unknown>)[name];
  return typeof value === 'string' ? value : undefined;
}
