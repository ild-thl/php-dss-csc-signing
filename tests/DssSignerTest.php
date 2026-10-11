<?php

declare(strict_types=1);

namespace IsyThl\Signing\Tests;

use IsyThl\Signing\CertificateProviderInterface;
use IsyThl\Signing\Csc\AsyncSigningProviderInterface;
use IsyThl\Signing\Csc\CscSigningOperation;
use IsyThl\Signing\DocumentValidatorInterface;
use IsyThl\Signing\Dss\DssSigner;
use IsyThl\Signing\Dss\DssSigningOperation;
use IsyThl\Signing\Exception\SigningException;
use IsyThl\Signing\Exception\ValidationException;
use IsyThl\Signing\SigningProviderInterface;
use IsyThl\Signing\TimestampProviderInterface;
use IsyThl\Signing\ValidationResult;
use PHPUnit\Framework\TestCase;

final class DssSignerTest extends TestCase {

    public function test_signing_preserves_dss_bytes_and_order(): void {
        $calls = [];
        $http = new FakeDssHttpClient($calls);
        $timestamp = new class ($calls) implements TimestampProviderInterface
        {
            public function __construct(private array &$calls) {
            }

            public function timestamp(string $document): array {
                $this->calls[] = 'timestamp';

                return [
                    'bytes' => 'timestamp-token',
                    'digestAlgorithm' => 'SHA512',
                    'timestampContainerForm' => null,
                ];
            }
        };
        $provider = new class ($calls) implements SigningProviderInterface
        {
            public string $input = '';

            public function __construct(private array &$calls) {
            }

            public function sign(string $data): string {
                $this->calls[] = 'sign';
                $this->input = $data;

                return 'signature-bytes';
            }

            public function signatureAlgorithm(): string {
                return 'RSA_SHA256';
            }
        };
        $certificateProvider = new class implements CertificateProviderInterface
        {
            public function certificateData(): array {
                return [
                    'certificate' => 'certificate',
                    'chain' => ['certificate', 'intermediate-certificate'],
                ];
            }
        };
        $signer = new DssSigner($http, $provider, 'https://dss.example', $certificateProvider, $timestamp);

        $result = $signer->sign('{"id":"credential","issuer":{"id":"untrusted"}}', [
            'issuer' => ['id' => 'trusted'],
            'issuanceDate' => '2030-01-01T00:00:00Z',
        ]);

        $this->assertSame('{"signed":true}', $result);
        $this->assertSame(['timestamp', 'getDataToSign', 'sign', 'signDocument'], $calls);
        $this->assertSame('dss-data-to-sign', $provider->input);
        $this->assertSame('trusted', $http->dataToSignDocument['issuer']['id']);
        $this->assertSame([
            base64_encode('certificate'),
            base64_encode('intermediate-certificate'),
        ], $http->certificateChain);
        $this->assertSame('JSON_SERIALIZATION', $http->jwsSerializationType);
        $this->assertTrue($http->base64UrlEncodedEtsiUComponents);
        $this->assertSame('RSA_SHA256', $http->signature['algorithm']);
        $this->assertSame(base64_encode('signature-bytes'), $http->signature['value']);
    }

    public function test_async_signing_can_be_polled_and_finalizes_the_document(): void {
        $calls = [];
        $http = new FakeDssHttpClient($calls);
        $provider = new class ($calls) implements AsyncSigningProviderInterface, SigningProviderInterface
        {
            public string $input = '';

            private int $pollCount = 0;

            public function __construct(private array &$calls) {
            }

            public function sign(string $data): string {
                throw new \LogicException('Synchronous signing should not be used.');
            }

            public function startSigning(string $data): CscSigningOperation {
                $this->calls[] = 'startSigning';
                $this->input = $data;

                return new CscSigningOperation('request-id', 'access-token');
            }

            public function pollSigning(CscSigningOperation $operation): ?string {
                $this->calls[] = 'pollSigning';

                return ++$this->pollCount === 1 ? null : 'signature-bytes';
            }

            public function revokeSigningOperation(CscSigningOperation $operation): void {
                $this->calls[] = 'revokeSigningOperation';
            }

            public function signatureAlgorithm(): string {
                return 'RSA_SHA256';
            }
        };
        $timestamp = new class ($calls) implements TimestampProviderInterface
        {
            public function __construct(private array &$calls) {
            }

            public function timestamp(string $document): array {
                $this->calls[] = 'timestamp';

                return ['bytes' => 'timestamp-token'];
            }
        };
        $validator = new class ($calls) implements DocumentValidatorInterface
        {
            public function __construct(private array &$calls) {
            }

            public function validate(string $signedDocument): ValidationResult {
                $this->calls[] = 'validate';

                return new ValidationResult(true, true);
            }
        };
        $signer = new DssSigner(
            $http,
            $provider,
            'https://dss.example',
            'certificate',
            $timestamp,
            null,
            $validator
        );

        $operation = $signer->startSigning('{"id":"credential"}', ['issuer' => ['id' => 'trusted']]);

        $this->assertInstanceOf(DssSigningOperation::class, $operation);
        $this->assertSame(['timestamp', 'getDataToSign', 'startSigning'], $calls);
        $this->assertSame('dss-data-to-sign', $provider->input);
        $this->assertNull($signer->pollSigning($operation));
        $this->assertSame(['timestamp', 'getDataToSign', 'startSigning', 'pollSigning'], $calls);

        $restoredOperation = unserialize(serialize($operation));
        $this->assertInstanceOf(DssSigningOperation::class, $restoredOperation);
        $this->assertSame('request-id', $restoredOperation->cscOperation->requestId);
        $this->assertSame('{"signed":true}', $signer->pollSigning($restoredOperation));
        $this->assertSame(
            ['timestamp', 'getDataToSign', 'startSigning', 'pollSigning', 'pollSigning', 'signDocument', 'validate'],
            $calls
        );
        $this->assertSame(base64_encode('signature-bytes'), $http->signature['value']);
        $this->assertSame('trusted', $http->dataToSignDocument['issuer']['id']);
    }

    public function test_invalid_json_is_rejected_before_dependencies_are_called(): void {
        $calls = [];
        $http = new FakeDssHttpClient($calls);
        $provider = new class implements SigningProviderInterface
        {
            public function sign(string $data): string {
                throw new \LogicException('must not sign');
            }

            public function signatureAlgorithm(): string {
                return 'RSA_SHA256';
            }
        };
        $signer = new DssSigner($http, $provider, 'https://dss.example', 'certificate');

        $this->expectException(SigningException::class);
        $signer->sign('{invalid');
        $this->assertSame([], $calls);
    }

    public function test_json_array_is_rejected_before_dependencies_are_called(): void {
        $calls = [];
        $http = new FakeDssHttpClient($calls);
        $provider = new class implements SigningProviderInterface
        {
            public function sign(string $data): string {
                throw new \LogicException('must not sign');
            }

            public function signatureAlgorithm(): string {
                return 'RSA_SHA256';
            }
        };
        $signer = new DssSigner($http, $provider, 'https://dss.example', 'certificate');

        $this->expectException(SigningException::class);
        $signer->sign('[]');
        $this->assertSame([], $calls);
    }

    public function test_dss_service_url_must_use_https(): void {
        $calls = [];
        $this->expectException(SigningException::class);
        $this->expectExceptionMessage('DSS service URL must use HTTPS.');
        new DssSigner(
            new FakeDssHttpClient($calls),
            new class implements SigningProviderInterface
            {
                public function sign(string $data): string {
                    return 'signature';
                }

                public function signatureAlgorithm(): string {
                    return 'RSA_SHA256';
                }
            },
            'http://dss.example',
            'certificate'
        );
    }

    public function test_insecure_dss_transport_requires_explicit_opt_in(): void {
        $calls = [];
        new DssSigner(
            new FakeDssHttpClient($calls),
            new class implements SigningProviderInterface
            {
                public function sign(string $data): string {
                    return 'signature';
                }

                public function signatureAlgorithm(): string {
                    return 'RSA_SHA256';
                }
            },
            'http://dss.example',
            'certificate',
            null,
            null,
            null,
            true
        );

        $this->addToAssertionCount(1);
    }

    public function test_empty_data_to_sign_response_is_rejected_before_signing(): void {
        $calls = [];
        $http = new FakeDssHttpClient($calls);
        $http->returnEmptyDataToSign = true;
        $provider = new class ($calls) implements SigningProviderInterface
        {
            public function __construct(private array &$calls) {
            }

            public function sign(string $data): string {
                $this->calls[] = 'sign';

                return 'signature';
            }

            public function signatureAlgorithm(): string {
                return 'RSA_SHA256';
            }
        };
        $signer = new DssSigner($http, $provider, 'https://dss.example', 'certificate');

        $this->expectException(SigningException::class);
        $this->expectExceptionMessage('DSS did not return data to sign.');
        try {
            $signer->sign('{"id":"credential"}');
        } finally {
            $this->assertNotContains('sign', $calls);
        }
    }

    public function test_ecdsa_provider_selects_ecdsa_dss_encryption_algorithm(): void {
        $calls = [];
        $http = new FakeDssHttpClient($calls);
        $provider = new class implements SigningProviderInterface
        {
            public function sign(string $data): string {
                return 'signature';
            }

            public function signatureAlgorithm(): string {
                return 'ECDSA_SHA256';
            }
        };
        $timestamp = new class implements TimestampProviderInterface
        {
            public function timestamp(string $document): array {
                return ['bytes' => 'timestamp'];
            }
        };
        $signer = new DssSigner($http, $provider, 'https://dss.example', 'certificate', $timestamp);

        $signer->sign('{"id":"credential"}');

        $this->assertSame('ECDSA', $http->encryptionAlgorithm);
    }

    public function test_signing_date_uses_injected_clock(): void {
        $calls = [];
        $http = new FakeDssHttpClient($calls);
        $signer = new DssSigner(
            $http,
            new class implements SigningProviderInterface
            {
                public function sign(string $data): string {
                    return 'signature';
                }

                public function signatureAlgorithm(): string {
                    return 'RSA_SHA256';
                }
            },
            'https://dss.example',
            'certificate',
            new class implements TimestampProviderInterface
            {
                public function timestamp(string $document): array {
                    return ['bytes' => 'timestamp'];
                }
            },
            static fn (): int => 1700000000123
        );

        $signer->sign('{"id":"credential"}');

        $this->assertSame(1700000000123, $http->signingDate);
    }

    public function test_signed_document_is_validated_before_it_is_returned(): void {
        $calls = [];
        $validator = new class ($calls) implements DocumentValidatorInterface
        {
            public function __construct(private array &$calls) {
            }

            public function validate(string $signedDocument): ValidationResult {
                $this->calls[] = 'validate';

                return new ValidationResult(true, true);
            }
        };
        $signer = new DssSigner(
            new FakeDssHttpClient($calls),
            new class implements SigningProviderInterface
            {
                public function sign(string $data): string {
                    return 'signature';
                }

                public function signatureAlgorithm(): string {
                    return 'RSA_SHA256';
                }
            },
            'https://dss.example',
            'certificate',
            new class implements TimestampProviderInterface
            {
                public function timestamp(string $document): array {
                    return ['bytes' => 'timestamp'];
                }
            },
            null,
            $validator
        );

        $this->assertSame('{"signed":true}', $signer->sign('{"id":"credential"}'));
        $this->assertContains('validate', $calls);
    }

    public function test_empty_signed_document_response_is_rejected(): void {
        $calls = [];
        $http = new FakeDssHttpClient($calls);
        $http->returnEmptySignedDocument = true;
        $signer = new DssSigner(
            $http,
            new class implements SigningProviderInterface
            {
                public function sign(string $data): string {
                    return 'signature';
                }

                public function signatureAlgorithm(): string {
                    return 'RSA_SHA256';
                }
            },
            'https://dss.example',
            'certificate',
            new class implements TimestampProviderInterface
            {
                public function timestamp(string $document): array {
                    return ['bytes' => 'timestamp'];
                }
            }
        );

        $this->expectException(SigningException::class);
        $this->expectExceptionMessage('DSS did not return a signed document.');
        $signer->sign('{"id":"credential"}');
    }

    public function test_validation_failure_prevents_signed_document_from_being_returned(): void {
        $calls = [];
        $validator = new class implements DocumentValidatorInterface
        {
            public function validate(string $signedDocument): ValidationResult {
                throw new ValidationException('DSS validation rejected the signed document.');
            }
        };
        $signer = new DssSigner(
            new FakeDssHttpClient($calls),
            new class implements SigningProviderInterface
            {
                public function sign(string $data): string {
                    return 'signature';
                }

                public function signatureAlgorithm(): string {
                    return 'RSA_SHA256';
                }
            },
            'https://dss.example',
            'certificate',
            new class implements TimestampProviderInterface
            {
                public function timestamp(string $document): array {
                    return ['bytes' => 'timestamp'];
                }
            },
            null,
            $validator
        );

        $this->expectException(ValidationException::class);
        $signer->sign('{"id":"credential"}');
    }
}
