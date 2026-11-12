import type { TokenVerifierOptions, VerifiedIdentity } from '@xignet/core';
import type {
  CollectionSlug,
  Payload,
  PayloadRequest,
  Plugin,
  TypedUser,
} from 'payload';

export type UserResolution<TUser extends TypedUser = TypedUser> =
  | { readonly status: 'allowed'; readonly user: TUser }
  | {
      readonly status: 'denied';
      readonly reason: 'unbound' | 'disabled' | 'not_allowed';
    };

export type ResolveUser<TUser extends TypedUser = TypedUser> = (input: {
  identity: VerifiedIdentity;
  channel: 'login' | 'mcp';
  payload: Payload;
  login?: { idTokenClaims: Readonly<Record<string, unknown>> };
}) => Promise<UserResolution<TUser>>;

export type MCPOperation = 'find' | 'create' | 'update';
export interface OperationPolicy {
  readonly scopes: readonly string[];
}

export interface MutationInput {
  readonly operation: 'create' | 'update';
  readonly data: Record<string, unknown>;
  readonly originalDoc?: Record<string, unknown>;
  readonly req: PayloadRequest;
  readonly identity: VerifiedIdentity;
}

/** Return additional required scopes, or false to refuse the mutation. */
export type MutationPolicy = (
  input: MutationInput,
) => readonly string[] | false | Promise<readonly string[] | false>;

export interface EntityPolicy {
  readonly find?: OperationPolicy;
  readonly create?: OperationPolicy;
  readonly update?: OperationPolicy;
  readonly mutationPolicy?: MutationPolicy;
}

export interface XignetPayloadOptions<
  TUser extends TypedUser = TypedUser,
> extends Omit<TokenVerifierOptions, 'audience'> {
  readonly resource: string;
  readonly admissionScopes: readonly string[];
  readonly userCollection: CollectionSlug;
  readonly resolveUser: ResolveUser<TUser>;
  readonly mcp: {
    readonly enabled: boolean;
    readonly collections: Readonly<Record<string, EntityPolicy>>;
    readonly globals?: Readonly<Record<string, Omit<EntityPolicy, 'create'>>>;
    /** Include scopes returned dynamically by mutationPolicy. */
    readonly scopesSupported?: readonly string[];
  };
}

export interface XignetPayloadIntegration {
  plugin(): Plugin;
  /** HTTP metadata response; mount at the resource's well-known path. */
  metadata(): Response;
}
