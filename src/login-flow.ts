import { type Logger } from '@nestjs/common';
import { type ConfigService } from '@nestjs/config';
import { type Request, type Response as ExpressResponse } from 'express';

import { type SignetDeploymentProfileService } from './deployment-profile';
import { type VerifiedSignetIdentity } from './jwt-verifier';
import { REFUSAL_ROUTE_MAX, sanitiseLogToken, truncate } from './log-sanitise';
import {
  LoginDiscovery,
  LoginDiscoveryError,
  type LoginEndpoints,
} from './login-discovery';
import {
  checkLoginEntryEnvironments,
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
  fetchJson,
  type JsonResponse,
  LoginTransportError,
} from './login-http';
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

// The state a callback answers, or which check failed, for the log line.
type StateMatch =
  | { readonly detail: string; readonly ok: false }
  | { readonly ok: true; readonly state: LoginState };

// The authorization-code + PKCE flow for one entry, as a public client:
// begin() starts it, complete() turns the IdP's redirect back into a verified
// identity. The admission scope is checked here (see verifiedIdentity());
// what happens to the identity after that -- the consumer's resolver -- is
// SignetDecision's, run by the strategy.
//
// The identity comes from the ACCESS token, verified by the same
// SignetBearerVerification the Bearer channel uses: the claims a resolver
// reads are the resource-server contract's either way. No ID token, no
// nonce, no refresh token is kept.
//
// Every refusal throws SignetLoginError through reject(), which writes the
// one rejection line. Nothing derived from the token, the code or the state
// is logged, and the route is the path alone: the callback's query carries
// the code. A defect in this package's own code is not a refusal: it
// propagates, and Nest answers 500.
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
    // Checked with the flag off too: the entry's environments, its URI and
    // the login variables' names are code, and a mistake in them should not
    // wait for the day the flag is turned on.
    checkLoginEntryEnvironments(entry, Object.keys(options.deployedProfiles));
    this.redirectUri = loginRedirectUri(entry, profile.environment);
    this.cookieName = loginStateCookieName(entry.name);
    this.canonicalResource = profile.canonicalResource;
    const names = options.env.login;
    if (names === undefined) {
      throw new Error(
        `SignetLoginStrategy ${entry.name} needs options.env.login ({ clientId, stateSecret })`,
      );
    }
    this.verification = new SignetBearerVerification(
      configService,
      profiles,
      options,
      logger,
    );
    const { enabled, issuer } = this.verification;
    if (!enabled || issuer === null) {
      this.settings = null;
      return;
    }
    const clientId = configService.getOrThrow<string>(names.clientId);
    if (clientId.trim() === '') {
      throw new Error(`${names.clientId} must not be empty`);
    }
    this.settings = {
      clientId,
      discovery: new LoginDiscovery(issuer, !development, timeouts.discoveryMs),
      key: loginStateKey(
        configService.getOrThrow<string>(names.stateSecret),
        names.stateSecret,
      ),
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

  // The callback: the state checked, the IdP's answer read, the code
  // exchanged, the token verified.
  async complete(request: Request): Promise<VerifiedSignetIdentity> {
    const settings = this.enabled(request);
    // Read, then cleared on the browser before any later check can fail
    // (only the enabled check runs first), so a browser never presents a
    // state twice. The server keeps no record of used states: a sealed
    // value opens until it expires, and what stops a replayed callback is
    // the IdP's single-use code.
    const sealed = readCookie(request.headers.cookie, this.cookieName);
    this.clearStateCookie(request);

    // The state before the IdP's answer, error responses included (RFC 6749
    // §4.1.2.1 has them carry it): an unchecked `error` would let any page
    // end a login in flight and have the UI say "you cancelled".
    const match = await this.matchState(
      settings,
      sealed,
      queryValue(request, 'state'),
    );
    if (!match.ok) {
      throw this.reject(
        request,
        SignetLoginFailureEnum.STATE_INVALID,
        match.detail,
      );
    }
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
      match.state.verifier,
    );
    return this.verifiedIdentity(settings, request, accessToken);
  }

  // The access token verified, then two checks the Bearer channel does not
  // make.
  private async verifiedIdentity(
    settings: LoginSettings,
    request: Request,
    accessToken: string,
  ): Promise<VerifiedSignetIdentity> {
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
  ): Promise<LoginEndpoints> {
    try {
      return await settings.discovery.endpoints();
    } catch (error) {
      // Every failure of the issuer's is a LoginDiscoveryError; anything
      // else is a defect here and must surface as a 500, not a 401.
      if (!(error instanceof LoginDiscoveryError)) throw error;
      throw this.reject(
        request,
        SignetLoginFailureEnum.DISCOVERY_FAILED,
        error.detail,
      );
    }
  }

  // Which check failed, distinctly, because each sends the operator
  // somewhere else (login-state.ts): no cookie at all (SameSite, Path, a
  // proxy), one that would not open (unopenable / expired / malformed),
  // none for this entry, none whose state is the query's. A stale cookie on
  // a wider path can arrive beside the current one, so every value is tried.
  private async matchState(
    settings: LoginSettings,
    sealed: readonly string[],
    queryState: string | undefined,
  ): Promise<StateMatch> {
    if (sealed.length === 0) return { detail: 'cookie_missing', ok: false };
    const opened: LoginState[] = [];
    let firstFailure: string | undefined;
    for (const value of sealed) {
      const opening = await openLoginState(settings.key, value);
      if (opening.ok) opened.push(opening.state);
      else firstFailure ??= opening.reason;
    }
    if (opened.length === 0) {
      return { detail: firstFailure ?? 'unopenable', ok: false };
    }
    const forEntry = opened.filter(({ entry }) => entry === this.entry.name);
    if (forEntry.length === 0) return { detail: 'entry', ok: false };
    const state = forEntry.find((s) => s.state === queryState);
    return state === undefined
      ? { detail: 'state', ok: false }
      : { ok: true, state };
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
    let response: JsonResponse;
    try {
      response = await fetchJson(
        tokenEndpoint,
        {
          body: new URLSearchParams({
            client_id: settings.clientId,
            code,
            code_verifier: verifier,
            grant_type: 'authorization_code',
            redirect_uri: this.redirectUri.value,
          }),
          method: 'POST',
        },
        this.timeouts.tokenMs,
      );
    } catch (error) {
      if (!(error instanceof LoginTransportError)) throw error;
      throw fail(error.detail);
    }
    const fields = (response.body ?? {}) as Record<string, unknown>;
    if (!response.ok) {
      // The status and the OAuth `error` code only: the body can echo the
      // code or carry a description written for humans.
      const oauthError =
        typeof fields.error === 'string' ? fields.error : 'none';
      throw fail(`status_${response.status}:${oauthError}`);
    }
    if (!response.json) throw fail('body_not_json');
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
