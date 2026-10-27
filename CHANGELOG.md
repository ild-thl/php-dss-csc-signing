# Changelog

## 0.2.1 - 2026-10-27

- Map DSS 6.5 validation report DTOs into the strict qualified issuance policy.
- Support an explicit unqualified mode while keeping signature, revocation, and
  timestamp checks mandatory; the strict policy remains the default.
- Include failed qualified-issuance policy gate names in validation errors
  without logging or exposing the underlying validation report.
- Bind certificate qualification, revocation, timestamps, and trusted-list
  evidence to the signing certificate and fail closed when evidence is missing
  or unrelated.
- Add DSS 6.5 DTO mapping and fail-closed regression tests.

## 0.2.0 - 2026-10-27

- Add a provider-neutral digest timestamp contract and RFC 3161 request/response
  bridge for applications exposing CSC-backed timestamping as a TSP source.
- Normalize direct CMS timestamp tokens and successful RFC 3161 responses,
  including Base64-wrapped provider responses, with strict DER/status checks.
- Add digest algorithm and length validation, reject unsupported policies,
  extensions, and nonce-bearing requests, and return RFC 3161 rejection
  responses for unsupported requests.
- Encode document timestamp bytes as Base64 in DSS JSON requests.

## 0.1.3 - 2026-10-11

- Make CSC `sign()` use synchronous signing and add explicit asynchronous
  initiation and polling APIs.
- Add resumable asynchronous DSS document signing with final document
  validation and CSC access-token revocation.
- Add tests for synchronous CSC responses and the document-level async flow.

## 0.1.2 - 2026-09-04

- Added framework-independent DSS and CSC signing contracts, typed exceptions,
  HTTP transport, secret resolution, logging, and validation boundaries.
- Added DSS timestamping, `getDataToSign`, CSC hash signing, and final
  `signDocument` orchestration with qualified-validation release gating.
- Added CSC PKCE authorization, bounded polling, token revocation, timestamping,
  certificate discovery, certificate-chain validation, and RSA/ECDSA mapping.
- Added HTTPS-by-default transport, explicit isolated-development DSS HTTP
  opt-in, positive HTTP timeouts, malformed-response rejection, and safe
  redacted lifecycle logging.
- Added certificate-purpose and signing-time qualification checks, evidence
  identifier requirements, certificate fingerprint pinning, and strict JSON
  object validation.
- Added CI, Composer validation, PHP linting, PHPCS, PHPStan, PHPUnit, and
  production no-dev installation checks.

## 0.1.0 - Unreleased

- Initial framework-independent DSS and CSC JAdES signing package.
- CSC v2 hash signing, timestamping, certificate discovery, PKCE, polling, and
  revocation support.
- DSS JAdES orchestration and validation release gate.
- RSA and ECDSA signing algorithm support.