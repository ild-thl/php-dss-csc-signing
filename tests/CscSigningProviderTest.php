<?php

declare(strict_types=1);

namespace IsyThl\Signing\Tests;

use IsyThl\Signing\Csc\CscSigningProvider;
use IsyThl\Signing\Exception\HttpException;
use IsyThl\Signing\Exception\SigningException;
use PHPUnit\Framework\TestCase;

final class CscSigningProviderTest extends TestCase {

    public function test_signing_endpoints_must_use_https(): void {
        $profile = $this->profile();
        $profile['api_url'] = 'http://api.example';

        $this->expectException(SigningException::class);
        $this->expectExceptionMessage('CSC endpoint must use HTTPS: api_url');
        new CscSigningProvider($profile, new FakeCscHttpClient([]), new FakeSecrets());
    }

    public function test_certificate_fingerprint_configuration_must_be_sha256(): void {
        $profile = $this->profile();
        $profile['certificate_sha256'] = 'not-a-fingerprint';

        $this->expectException(SigningException::class);
        $this->expectExceptionMessage('CSC certificate fingerprint must be a SHA-256 value.');
        new CscSigningProvider($profile, new FakeCscHttpClient([]), new FakeSecrets());
    }

    public function test_signs_only_the_digest_uses_profile_values_and_revokes(): void {
        $client = new FakeCscHttpClient([
            ['code' => 'authorization-code'],
            ['access_token' => 'access-token'],
            ['signatures' => [base64_encode('signature-bytes')]],
            [],
        ]);
        $provider = new CscSigningProvider($this->profile(), $client, new FakeSecrets());

        $this->assertSame('signature-bytes', $provider->sign('DSS data to sign'));
        $signRequest = $client->requests[2];
        $this->assertSame('S', $signRequest['data']['operationMode']);
        $this->assertSame('credential-id', $signRequest['data']['credentialID']);
        $this->assertSame('profile-sign-algorithm', $signRequest['data']['signAlgo']);
        $this->assertSame(base64_encode(hash('sha256', 'DSS data to sign', true)), $signRequest['data']['hashes'][0]);
        $this->assertArrayNotHasKey('document', $signRequest['data']);
        $this->assertSame('/oauth2/revoke', $client->requests[3]['path']);
        $this->assertCount(4, $client->requests);
    }

    public function test_synchronous_signing_uses_inline_signature_without_polling(): void {
        $encodedSignature = 'MEUCIQCvBTyLfpvFg4layFlfPnhIUmg247WhkcuD5/Q4IhY04gIgX5CqT0Jx1YmaUSIXwzL+'
            . 'ud3Rs0hNDgHZglmGbHowEhM=';
        $client = new FakeCscHttpClient([
            ['code' => 'authorization-code'],
            ['access_token' => 'access-token'],
            ['signatures' => [$encodedSignature]],
            [],
        ]);
        $profile = $this->profile();
        $provider = new CscSigningProvider($profile, $client, new FakeSecrets());

        $this->assertSame(base64_decode($encodedSignature, true), $provider->sign('DSS data to sign'));
        $this->assertSame('S', $client->requests[2]['data']['operationMode']);
        $this->assertSame('/csc/v2/signatures/signHash', $client->requests[2]['path']);
        $this->assertSame('/oauth2/revoke', $client->requests[3]['path']);
        $this->assertCount(4, $client->requests);
    }

    public function test_synchronous_signing_requires_an_inline_signature(): void {
        $client = new FakeCscHttpClient([
            ['code' => 'authorization-code'],
            ['access_token' => 'access-token'],
            ['responseID' => 'request-id'],
            [],
        ]);
        $profile = $this->profile();
        $provider = new CscSigningProvider($profile, $client, new FakeSecrets());

        $this->expectExceptionMessage('CSC did not return a signature.');
        try {
            $provider->sign('DSS data to sign');
        } finally {
            $this->assertSame('/oauth2/revoke', $client->requests[3]['path']);
            $this->assertCount(4, $client->requests);
        }
    }

    public function test_async_signing_can_be_started_and_polled_without_blocking(): void {
        $client = new FakeCscHttpClient([
            ['code' => 'authorization-code'],
            ['access_token' => 'access-token'],
            ['responseID' => 'request-id'],
            new HttpException(
                'HTTP request failed with status 400; provider error: invalid_request: The previous asynchronous '
                . 'signature request has been accepted for processing, but the processing has not yet been completed.',
                400
            ),
            ['signatures' => [base64_encode('signature-bytes')]],
            [],
        ]);
        $provider = new CscSigningProvider($this->profile(), $client, new FakeSecrets());

        $operation = $provider->startSigning('DSS data to sign');
        $this->assertSame('request-id', $operation->requestId);
        $this->assertSame('access-token', $operation->accessToken);
        $this->assertSame('A', $client->requests[2]['data']['operationMode']);
        $this->assertCount(3, $client->requests);

        $this->assertNull($provider->pollSigning($operation));
        $this->assertSame('request-id', $client->requests[3]['data']['requestID']);
        $this->assertSame('signature-bytes', $provider->pollSigning($operation));
        $this->assertSame('/oauth2/revoke', $client->requests[5]['path']);
    }

    public function test_timestamp_posts_json_and_decodes_the_base64_token(): void {
        $client = new FakeCscHttpClient([
            ['code' => 'authorization-code'],
            ['access_token' => 'access-token'],
            ['timeStampToken' => base64_encode('timestamp-token')],
            [],
        ]);
        $provider = new CscSigningProvider($this->profile(), $client, new FakeSecrets());

        $this->assertSame([
            'bytes' => 'timestamp-token',
            'digestAlgorithm' => 'SHA512',
            'timestampContainerForm' => null,
        ], $provider->timestamp('document-bytes'));
        $this->assertSame('json', $client->requests[2]['transport']);
        $this->assertSame('/csc/v2/signatures/timestamp', $client->requests[2]['path']);
        $authorization = $client->requests[0]['data'];
        $token = $client->requests[1]['data'];
        $this->assertSame(
            rtrim(strtr(base64_encode(hash('sha256', $token['code_verifier'], true)), '+/', '-_'), '='),
            $authorization['code_challenge']
        );
        $this->assertArrayNotHasKey('user-agent', $token);
        $this->assertSame(base64_encode(hash('sha512', 'document-bytes', true)), $client->requests[2]['data']['hash']);
        $this->assertSame('2.16.840.1.101.3.4.2.3', $client->requests[2]['data']['hashAlgo']);
        $this->assertSame('/oauth2/revoke', $client->requests[3]['path']);
    }

    public function test_invalid_base64_timestamp_response_is_rejected_and_authorization_revoked(): void {
        $client = new FakeCscHttpClient([
            ['code' => 'authorization-code'],
            ['access_token' => 'access-token'],
            ['timeStampToken' => '%%%'],
            [],
        ]);
        $provider = new CscSigningProvider($this->profile(), $client, new FakeSecrets());

        $this->expectExceptionMessage('CSC returned an invalid timestamp token.');
        try {
            $provider->timestamp('document-bytes');
        } finally {
            $this->assertSame('/oauth2/revoke', $client->requests[3]['path']);
        }
    }

    public function test_empty_signature_response_fails_immediately(): void {
        $client = new FakeCscHttpClient([
            ['code' => 'authorization-code'],
            ['access_token' => 'access-token'],
            ['responseID' => 'request-id'],
            ['signatures' => []],
            [],
        ]);
        $provider = new CscSigningProvider($this->profile(), $client, new FakeSecrets());
        $operation = $provider->startSigning('DSS data to sign');

        $this->expectExceptionMessage('CSC returned an empty signature response.');
        try {
            $provider->pollSigning($operation);
        } finally {
            $provider->revokeSigningOperation($operation);
            $this->assertCount(5, $client->requests);
            $this->assertSame('/oauth2/revoke', $client->requests[4]['path']);
        }
    }

    public function test_empty_encoded_signature_does_not_succeed(): void {
        $client = new FakeCscHttpClient([
            ['code' => 'authorization-code'],
            ['access_token' => 'access-token'],
            ['responseID' => 'request-id'],
            ['signatures' => ['']],
        ]);
        $provider = new CscSigningProvider($this->profile(), $client, new FakeSecrets());
        $operation = $provider->startSigning('DSS data to sign');

        $this->expectExceptionMessage('CSC returned an invalid signature.');
        $provider->pollSigning($operation);
    }

    public function test_certificate_data_discovers_and_caches_the_configured_chain(): void {
        $client = new FakeCscHttpClient([
            ['code' => 'authorization-code'],
            ['access_token' => 'access-token'],
            ['cert' => ['certificates' => [$this->certificateDerBase64(), $this->certificateDerBase64()]]],
            [],
        ]);
        $provider = new CscSigningProvider($this->profile(), $client, new FakeSecrets());

        $certificateData = $provider->certificateData();
        $this->assertStringContainsString('-----BEGIN CERTIFICATE-----', $certificateData['certificate']);
        $this->assertCount(2, $certificateData['chain']);
        $this->assertSame('/csc/v2/credentials/info', $client->requests[2]['path']);
        $this->assertSame('credential-id', $client->requests[2]['data']['credentialID']);
        $this->assertSame('/oauth2/revoke', $client->requests[3]['path']);
        $this->assertSame($certificateData, $provider->certificateData());
        $this->assertCount(4, $client->requests);
    }

    public function test_certificate_fingerprint_mismatch_is_rejected(): void {
        $client = new FakeCscHttpClient([
            ['code' => 'authorization-code'],
            ['access_token' => 'access-token'],
            ['cert' => ['certificates' => [$this->certificateDerBase64()]]],
            [],
        ]);
        $profile = $this->profile();
        $profile['certificate_sha256'] = str_repeat('0', 64);
        $provider = new CscSigningProvider($profile, $client, new FakeSecrets());

        $this->expectException(SigningException::class);
        $this->expectExceptionMessage('CSC certificate does not match the configured fingerprint.');
        $provider->certificateData();
    }

    public function test_certificate_fingerprint_accepts_normalized_matching_value(): void {
        $client = new FakeCscHttpClient([
            ['code' => 'authorization-code'],
            ['access_token' => 'access-token'],
            ['cert' => ['certificates' => [$this->certificateDerBase64()]]],
            [],
        ]);
        $profile = $this->profile();
        $profile['certificate_sha256'] = '1B:76:3C:AD:D9:41:3F:0B:F6:B0:54:B4:E0:C1:D9:CE:D3:'
            . '0D:A3:60:11:E5:CF:31:FE:69:1C:0C:5B:69:A1:82';
        $provider = new CscSigningProvider($profile, $client, new FakeSecrets());

        $certificateData = $provider->certificateData();

        $this->assertCount(1, $certificateData['chain']);
    }

    public function test_unrelated_certificate_chain_is_rejected(): void {
        $client = new FakeCscHttpClient([
            ['code' => 'authorization-code'],
            ['access_token' => 'access-token'],
            ['cert' => ['certificates' => [
                $this->certificateDerBase64('test-chain-leaf.pem'),
                $this->certificateDerBase64('test-certificate.pem'),
            ]]],
            [],
        ]);
        $provider = new CscSigningProvider($this->profile(), $client, new FakeSecrets());

        $this->expectException(SigningException::class);
        $this->expectExceptionMessage('CSC returned an invalid certificate chain.');
        $provider->certificateData();
    }

    public function test_ecdsa_certificate_chain_is_parseable(): void {
        $client = new FakeCscHttpClient([
            ['code' => 'authorization-code'],
            ['access_token' => 'access-token'],
            ['cert' => ['certificates' => [$this->certificateDerBase64('test-ecdsa-certificate.pem')]]],
            [],
        ]);
        $profile = $this->profile();
        $profile['sign_algo'] = '1.2.840.10045.4.3.2';
        $provider = new CscSigningProvider($profile, $client, new FakeSecrets());

        $certificateData = $provider->certificateData();
        $this->assertStringContainsString('-----BEGIN CERTIFICATE-----', $certificateData['certificate']);
        $this->assertCount(1, $certificateData['chain']);
    }

    private function certificateDerBase64(string $filename = 'test-certificate.pem'): string {
        $pem = file_get_contents(__DIR__ . '/fixtures/' . $filename);
        $der = preg_replace('/-----[^-]+-----|\s+/', '', (string) $pem);

        return base64_encode((string) base64_decode((string) $der, true));
    }

    public function test_malformed_certificate_chain_is_rejected(): void {
        $client = new FakeCscHttpClient([
            ['code' => 'authorization-code'],
            ['access_token' => 'access-token'],
            ['cert' => ['certificates' => [base64_encode('not-a-certificate')]]],
            [],
        ]);
        $provider = new CscSigningProvider($this->profile(), $client, new FakeSecrets());

        $this->expectException(SigningException::class);
        $this->expectExceptionMessage('CSC returned an invalid certificate.');
        $provider->certificateData();
    }

    public function test_signature_algorithm_maps_the_profile_key_algorithm(): void {
        $profile = $this->profile();
        $profile['sign_algo'] = '1.2.840.10045.4.3.2';
        $provider = new CscSigningProvider($profile, new FakeCscHttpClient([]), new FakeSecrets());

        $this->assertSame('ECDSA_SHA256', $provider->signatureAlgorithm());
    }

    public function test_signature_algorithm_override_must_match_csc_key_algorithm(): void {
        $profile = $this->profile();
        $profile['sign_algo'] = '1.2.840.113549.1.1.1';
        $profile['dss_signature_algorithm'] = 'ECDSA_SHA256';
        $provider = new CscSigningProvider($profile, new FakeCscHttpClient([]), new FakeSecrets());

        $this->expectException(SigningException::class);
        $this->expectExceptionMessage('DSS and CSC signing algorithms do not match.');
        $provider->signatureAlgorithm();
    }

    private function profile(): array {
        return [
            'credential_id' => 'credential-id',
            'client_id' => 'client-id',
            'oauth2_url' => 'https://oauth.example',
            'api_url' => 'https://api.example',
            'redirect_uri' => 'https://client.example/callback',
            'sign_algo' => 'profile-sign-algorithm',
            'client_secret' => 'client_secret',
            'tls_certificate' => 'tls_certificate',
            'tls_key' => 'tls_key',
        ];
    }
}
