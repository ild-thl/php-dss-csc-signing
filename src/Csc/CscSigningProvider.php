<?php

declare(strict_types=1);

namespace IsyThl\Signing\Csc;

use IsyThl\Signing\CertificateProviderInterface;
use IsyThl\Signing\Exception\HttpException;
use IsyThl\Signing\Exception\SigningException;
use IsyThl\Signing\Http\HttpClientInterface;
use IsyThl\Signing\Security\SecretResolverInterface;
use IsyThl\Signing\SigningProviderInterface;
use IsyThl\Signing\TimestampProviderInterface;

final class CscSigningProvider implements
    AsyncSigningProviderInterface,
    CertificateProviderInterface,
    SigningProviderInterface,
    TimestampProviderInterface {

    private const SHA256_OID = '2.16.840.1.101.3.4.2.1';

    private const SHA512_OID = '2.16.840.1.101.3.4.2.3';

    private const OPERATION_MODE_SYNCHRONOUS = 'S';

    private const OPERATION_MODE_ASYNCHRONOUS = 'A';

    /** @var array{certificate: string, chain: array<int, string>}|null */
    private ?array $certificateData = null;

    /**
     * @param  array<string, mixed>  $profile
     */
    public function __construct(
        private array $profile,
        private HttpClientInterface $httpClient,
        private SecretResolverInterface $secrets
    ) {
        foreach (
            [
                'credential_id', 'client_id', 'oauth2_url', 'api_url', 'redirect_uri', 'sign_algo', 'client_secret',
                'tls_certificate', 'tls_key',
            ] as $field
        ) {
            if (! isset($profile[$field]) || ! is_string($profile[$field]) || $profile[$field] === '') {
                throw new SigningException('CSC profile is missing: ' . $field);
            }
        }
        foreach (['oauth2_url', 'api_url'] as $endpoint) {
            if (parse_url($profile[$endpoint], PHP_URL_SCHEME) !== 'https') {
                throw new SigningException('CSC endpoint must use HTTPS: ' . $endpoint);
            }
        }
        if (isset($profile['certificate_sha256'])) {
            $fingerprint = strtolower(str_replace([':', ' '], '', (string) $profile['certificate_sha256']));
            if (preg_match('/\A[0-9a-f]{64}\z/D', $fingerprint) !== 1) {
                throw new SigningException('CSC certificate fingerprint must be a SHA-256 value.');
            }
        }
    }

    public function sign(string $data): string {
        if ($data === '') {
            throw new SigningException('Cannot sign empty data.');
        }
        $hash = hash('sha256', $data, true);
        $token = $this->authorize([$hash], self::SHA256_OID);
        try {
            $response = $this->httpClient->postJson($this->url('api_url', '/csc/v2/signatures/signHash'), [
                'credentialID' => $this->profile['credential_id'],
                'hashes' => [base64_encode($hash)],
                'hashAlgorithmOID' => self::SHA256_OID,
                'signAlgo' => $this->profile['sign_algo'],
                'operationMode' => self::OPERATION_MODE_SYNCHRONOUS,
            ], $this->bearer($token));

            return $this->signatureFromResponse($response);
        } finally {
            $this->revoke($token);
        }
    }

    /**
     * Initiate asynchronous signing without waiting for the signature.
     * The returned operation contains an access token and must be handled as a secret.
     */
    public function startSigning(string $data): CscSigningOperation {
        if ($data === '') {
            throw new SigningException('Cannot sign empty data.');
        }
        $hash = hash('sha256', $data, true);
        $token = $this->authorize([$hash], self::SHA256_OID);
        try {
            $response = $this->httpClient->postJson($this->url('api_url', '/csc/v2/signatures/signHash'), [
                'credentialID' => $this->profile['credential_id'],
                'hashes' => [base64_encode($hash)],
                'hashAlgorithmOID' => self::SHA256_OID,
                'signAlgo' => $this->profile['sign_algo'],
                'operationMode' => self::OPERATION_MODE_ASYNCHRONOUS,
            ], $this->bearer($token));
            $requestId = $response['responseID'] ?? null;
            if (! is_string($requestId) || $requestId === '') {
                throw new SigningException('CSC did not return a signing request identifier.');
            }

            return new CscSigningOperation($requestId, $token);
        } catch (\Throwable $exception) {
            $this->revoke($token);
            throw $exception;
        }
    }

    /** Returns null while the CSC request is still pending. */
    public function pollSigning(CscSigningOperation $operation): ?string {
        $signature = $this->pollOperation($operation->accessToken, $operation->requestId);
        if ($signature !== null) {
            $this->revoke($operation->accessToken);
        }

        return $signature;
    }

    /** Revoke the access token when an asynchronous operation will not be polled again. */
    public function revokeSigningOperation(CscSigningOperation $operation): void {
        $this->revoke($operation->accessToken);
    }

    public function signatureAlgorithm(): string {
        if (! empty($this->profile['dss_signature_algorithm'])) {
            $configured = (string) $this->profile['dss_signature_algorithm'];
            if (! in_array($configured, ['RSA_SHA256', 'ECDSA_SHA256'], true)) {
                throw new SigningException('DSS signing algorithm is not supported.');
            }
            $mapped = $this->mappedSignatureAlgorithm();
            if ($mapped !== null && $mapped !== $configured) {
                throw new SigningException('DSS and CSC signing algorithms do not match.');
            }

            return $configured;
        }

        return $this->mappedSignatureAlgorithm()
            ?? throw new SigningException('CSC signing algorithm is not supported.');
    }

    private function mappedSignatureAlgorithm(): ?string {
        return match ($this->profile['sign_algo']) {
            '1.2.840.10045.4.3.2' => 'ECDSA_SHA256',
            '1.2.840.113549.1.1.1' => 'RSA_SHA256',
            default => null,
        };
    }

    public function certificateData(): array {
        if ($this->certificateData !== null) {
            return $this->certificateData;
        }
        $token = $this->authorize([hash('sha256', 'certificate-info', true)], self::SHA256_OID);
        try {
            $response = $this->httpClient->postJson($this->url('api_url', '/csc/v2/credentials/info'), [
                'credentialID' => $this->profile['credential_id'],
                'certificates' => 'chain',
                'certInfo' => true,
                'authInfo' => false,
            ], $this->bearer($token));
            $encodedChain = $response['cert']['certificates'] ?? $response['certificates'] ?? null;
            if (! is_array($encodedChain) || $encodedChain === []) {
                throw new SigningException('CSC did not return a certificate chain.');
            }
            $chain = [];
            foreach ($encodedChain as $encodedCertificate) {
                if (! is_string($encodedCertificate)) {
                    throw new SigningException('CSC returned a malformed certificate chain.');
                }
                $der = base64_decode($encodedCertificate, true);
                if ($der === false || $der === '') {
                    throw new SigningException('CSC returned an invalid certificate.');
                }
                $certificate = $this->pem($der);
                if (@openssl_x509_read($certificate) === false) {
                    throw new SigningException('CSC returned an invalid certificate.');
                }
                $chain[] = $certificate;
            }
            if (isset($this->profile['certificate_sha256'])) {
                $expectedFingerprint = strtolower((string) $this->profile['certificate_sha256']);
                $expectedFingerprint = str_replace([':', ' '], '', $expectedFingerprint);
                $actualFingerprint = @openssl_x509_fingerprint($chain[0], 'sha256');
                if (
                    ! is_string($actualFingerprint)
                    || strtolower(str_replace(':', '', $actualFingerprint)) !== $expectedFingerprint
                ) {
                    throw new SigningException('CSC certificate does not match the configured fingerprint.');
                }
            }
            for ($index = 0, $last = count($chain) - 1; $index < $last; $index++) {
                $certificate = @openssl_x509_parse($chain[$index]);
                $issuer = @openssl_x509_parse($chain[$index + 1]);
                $issuerKey = @openssl_pkey_get_public($chain[$index + 1]);
                if (
                    ! is_array($certificate) || ! is_array($issuer)
                    || $issuerKey === false
                    || ($certificate['issuer'] ?? null) !== ($issuer['subject'] ?? null)
                    || @openssl_x509_verify($chain[$index], $issuerKey) !== 1
                ) {
                    throw new SigningException('CSC returned an invalid certificate chain.');
                }
            }

            return $this->certificateData = [
                'certificate' => $chain[0],
                'chain' => $chain,
            ];
        } finally {
            $this->revoke($token);
        }
    }

    public function timestamp(string $data): array {
        if ($data === '') {
            throw new SigningException('Cannot timestamp empty data.');
        }
        $hash = hash('sha512', $data, true);
        $token = $this->authorize([$hash], self::SHA512_OID);
        try {
            $response = $this->httpClient->postForm($this->url('api_url', '/csc/v2/signatures/timestamp'), [
                'hash' => base64_encode($hash),
                'hashAlgo' => self::SHA512_OID,
            ], $this->bearer($token));
            $timestamp = $response['timeStampToken'] ?? null;
            if (! is_string($timestamp) || $timestamp === '') {
                throw new SigningException('CSC did not return a timestamp token.');
            }

            return [
                'bytes' => $timestamp,
                'digestAlgorithm' => 'SHA512',
                'timestampContainerForm' => null,
            ];
        } finally {
            $this->revoke($token);
        }
    }

    /** @param array<int, string> $hashes */
    private function authorize(array $hashes, string $hashAlgorithm): string {
        $verifier = $this->base64url(random_bytes(32));
        $response = $this->httpClient->postJson($this->url('oauth2_url', '/oauth2/authorize_tls'), [
            'response_type' => 'code',
            'client_id' => $this->profile['client_id'],
            'redirect_uri' => $this->profile['redirect_uri'],
            'scope' => 'credential',
            'code_challenge' => $this->base64url(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
            'numSignatures' => (string) count($hashes),
            'hashAlgorithmOID' => $hashAlgorithm,
            'hashes' => implode(',', array_map(fn (string $hash): string => $this->base64url($hash), $hashes)),
            'state' => bin2hex(random_bytes(16)),
            'credentialID' => $this->profile['credential_id'],
        ], [], $this->tlsOptions());
        $code = $response['code'] ?? null;
        if (! is_string($code) || $code === '') {
            throw new SigningException('CSC did not return an authorization code.');
        }
        $token = $this->httpClient->postForm($this->url('oauth2_url', '/oauth2/token'), [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'client_id' => $this->profile['client_id'],
            'client_secret' => $this->secrets->resolve($this->profile['client_secret']),
            'redirect_uri' => $this->profile['redirect_uri'],
            'code_verifier' => $verifier,
        ]);
        $accessToken = $token['access_token'] ?? null;
        if (! is_string($accessToken) || $accessToken === '') {
            throw new SigningException('CSC did not return an access token.');
        }

        return $accessToken;
    }

    /** @param array<string, mixed> $response */
    private function signatureFromResponse(array $response): string {
        if (array_key_exists('signatures', $response) && $response['signatures'] === []) {
            throw new SigningException('CSC returned an empty signature response.');
        }
        $signature = $response['signatures'][0] ?? null;
        if (! is_string($signature)) {
            throw new SigningException('CSC did not return a signature.');
        }
        $decoded = $this->decode($signature);
        if ($decoded === false || $decoded === '') {
            throw new SigningException('CSC returned an invalid signature.');
        }

        return $decoded;
    }

    private function pollOperation(string $token, string $requestId): ?string {
        try {
            $response = $this->httpClient->postJson($this->url('api_url', '/csc/v2/signatures/signPolling'), [
                'requestID' => $requestId,
            ], $this->bearer($token));
        } catch (HttpException $exception) {
            if (
                $exception->statusCode === 400 && str_contains(
                    strtolower($exception->getMessage()),
                    'previous asynchronous signature request'
                )
            ) {
                return null;
            }
            throw $exception;
        }

        if (! array_key_exists('signatures', $response)) {
            return null;
        }
        if (! is_array($response['signatures'])) {
            throw new SigningException('CSC returned an invalid signature response.');
        }
        if ($response['signatures'] === []) {
            throw new SigningException('CSC returned an empty signature response.');
        }
        $signature = $response['signatures'][0] ?? null;
        if (! is_string($signature)) {
            throw new SigningException('CSC returned an invalid signature response.');
        }
        $decoded = $this->decode($signature);
        if ($decoded === false || $decoded === '') {
            throw new SigningException('CSC returned an invalid signature.');
        }

        return $decoded;
    }

    private function revoke(string $token): void {
        try {
            $this->httpClient->postForm($this->url('oauth2_url', '/oauth2/revoke'), [
                'token' => $token,
                'token_type_hint' => 'access_token',
                'client_id' => $this->profile['client_id'],
                'client_secret' => $this->secrets->resolve($this->profile['client_secret']),
            ], $this->bearer($token));
        } catch (\Throwable) {
        }
    }

    /** @return array<int, string> */
    private function bearer(string $token): array {
        return ['Authorization: Bearer ' . $token];
    }

    /** @return array<string, string|null> */
    private function tlsOptions(): array {
        return [
            'certificate' => $this->secrets->resolve($this->profile['tls_certificate']),
            'key' => $this->secrets->resolve($this->profile['tls_key']),
            'ca_info' => isset($this->profile['tls_ca'])
                ? $this->secrets->resolve((string) $this->profile['tls_ca'])
                : null,
        ];
    }

    private function url(string $base, string $path): string {
        return rtrim((string) $this->profile[$base], '/') . $path;
    }

    private function base64url(string $value): string {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function decode(string $value): string|false {
        $decoded = base64_decode($value, true);
        if ($decoded !== false) {
            return $decoded;
        }
        $normalized = strtr($value, '-_', '+/');
        $normalized .= str_repeat('=', (4 - strlen($normalized) % 4) % 4);

        return base64_decode($normalized, true);
    }

    private function pem(string $der): string {
        return "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END CERTIFICATE-----\n";
    }
}
