export interface JwtSettings {
  // Canonical resource URI; deployment config checks are owned by the caller.
  readonly audience: string;
  readonly clockToleranceS: number;
  readonly issuer: string;
  readonly jwksUri: string;
}
