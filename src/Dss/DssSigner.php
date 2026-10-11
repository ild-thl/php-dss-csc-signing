<?php

declare(strict_types=1);

namespace IsyThl\Signing\Dss;

use IsyThl\Signing\CertificateProviderInterface;
use IsyThl\Signing\Csc\AsyncSigningProviderInterface;
use IsyThl\Signing\DocumentValidatorInterface;
use IsyThl\Signing\Exception\SigningException;
use IsyThl\Signing\Http\HttpClientInterface;
use IsyThl\Signing\SigningProviderInterface;
use IsyThl\Signing\TimestampProviderInterface;

final class DssSigner {

    private string $certificate;

    /** @var array<int, string> */
    private array $certificateChain;

    private ?CertificateProviderInterface $certificateProvider = null;

    /**
     * @param  callable(): int|null  $clock  Returns signing time in milliseconds.
     */
    public function __construct(
        private HttpClientInterface $httpClient,
        private SigningProviderInterface $signingProvider,
        private string $serviceUrl,
        string|CertificateProviderInterface $certificate,
        private ?TimestampProviderInterface $timestampProvider = null,
        private $clock = null,
        private ?DocumentValidatorInterface $validator = null,
        private bool $allowInsecureTransport = false
    ) {
        if (
            $serviceUrl === ''
            || (! $this->allowInsecureTransport && parse_url($serviceUrl, PHP_URL_SCHEME) !== 'https')
        ) {
            throw new SigningException('DSS service URL must use HTTPS.');
        }
        if ($certificate instanceof CertificateProviderInterface) {
            $this->certificateProvider = $certificate;
            $this->certificate = '';
            $this->certificateChain = [];
        } else {
            if ($certificate === '') {
                throw new SigningException('DSS signing certificate is missing.');
            }
            $this->certificate = $certificate;
            $this->certificateChain = [$certificate];
        }
        $this->clock ??= static fn (): int => time() * 1000;
    }

    /**
     * @param  array<string, mixed>  $trustedMetadata
     */
    public function sign(string $document, array $trustedMetadata = []): string {
        $signingData = $this->prepareSigning($document, $trustedMetadata);
        $signature = $this->signingProvider->sign($signingData['dataToSign']);

        return $this->completeSigning($signingData['requestBody'], $signature);
    }

    /**
     * Begin a document signing operation without waiting for CSC hash signing to finish.
     * The returned operation contains the document request and CSC access token; treat it as sensitive.
     *
     * @param  array<string, mixed>  $trustedMetadata
     */
    public function startSigning(string $document, array $trustedMetadata = []): DssSigningOperation {
        $provider = $this->asyncSigningProvider();
        $signingData = $this->prepareSigning($document, $trustedMetadata);
        $operation = $provider->startSigning($signingData['dataToSign']);

        return new DssSigningOperation($signingData['requestBody'], $operation);
    }

    /** Returns null while CSC is processing, or the validated signed document when complete. */
    public function pollSigning(DssSigningOperation $operation): ?string {
        $signature = $this->asyncSigningProvider()->pollSigning($operation->cscOperation);
        if ($signature === null) {
            return null;
        }

        return $this->completeSigning($operation->requestBody, $signature);
    }

    /** Revoke CSC authorization if an asynchronous document operation is abandoned. */
    public function revokeSigningOperation(DssSigningOperation $operation): void {
        $this->asyncSigningProvider()->revokeSigningOperation($operation->cscOperation);
    }

    /**
     * @param  array<string, mixed>  $trustedMetadata
     * @return array{requestBody: array<string, mixed>, dataToSign: string}
     */
    private function prepareSigning(string $document, array $trustedMetadata): array {
        $documentData = json_decode($document, true);
        if (json_last_error() !== JSON_ERROR_NONE || ! is_array($documentData) || array_is_list($documentData)) {
            throw new SigningException('Document must be a JSON object.');
        }

        $documentData = array_merge($documentData, $trustedMetadata);
        $serializedDocument = json_encode(
            $documentData,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
        );
        $timestampData = $this->timestamp($serializedDocument);
        $requestBody = $this->requestBody($serializedDocument, $timestampData);
        $dataToSignResponse = $this->httpClient->postJson($this->url('/one-document/getDataToSign'), $requestBody);
        $dataToSign = $this->decodeBytes($dataToSignResponse, 'DSS did not return data to sign.');

        return ['requestBody' => $requestBody, 'dataToSign' => $dataToSign];
    }

    /** @param array<string, mixed> $requestBody */
    private function completeSigning(array $requestBody, string $signature): string {
        $requestBody['signatureValue'] = [
            'algorithm' => $this->signingProvider->signatureAlgorithm(),
            'value' => base64_encode($signature),
        ];
        $signedResponse = $this->httpClient->postJson($this->url('/one-document/signDocument'), $requestBody);
        $signedDocument = $this->decodeBytes($signedResponse, 'DSS did not return a signed document.');
        if ($this->validator !== null) {
            $this->validator->validate($signedDocument);
        }

        return $signedDocument;
    }

    private function asyncSigningProvider(): AsyncSigningProviderInterface {
        if (! $this->signingProvider instanceof AsyncSigningProviderInterface) {
            throw new SigningException('Signing provider does not support asynchronous signing.');
        }

        return $this->signingProvider;
    }

    /**
     * @param  array<string, mixed>  $timestampData
     * @return array<string, mixed>
     */
    private function requestBody(string $document, array $timestampData): array {
        $this->loadCertificateData();

        return [
            'parameters' => [
                'signingCertificate' => ['encodedCertificate' => base64_encode($this->certificate)],
                'certificateChain' => array_map(static fn (string $certificate): array => [
                    'encodedCertificate' => base64_encode($certificate),
                ], $this->certificateChain),
                'detachedContents' => null,
                'asicContainerType' => null,
                'signatureLevel' => 'JAdES_BASELINE_LTA',
                'signaturePackaging' => 'ENVELOPING',
                'embedXML' => false,
                'manifestSignature' => false,
                'jwsSerializationType' => 'JSON_SERIALIZATION',
                'sigDMechanism' => null,
                'base64UrlEncodedPayload' => false,
                'base64UrlEncodedEtsiUComponents' => true,
                'digestAlgorithm' => 'SHA256',
                'encryptionAlgorithm' => $this->encryptionAlgorithm(),
                'referenceDigestAlgorithm' => null,
                'contentTimestamps' => [[
                    'binaries' => base64_encode(
                        $timestampData['bytes'] ?? throw new SigningException('Timestamp bytes are missing.')
                    ),
                    'type' => 'DOCUMENT_TIMESTAMP',
                    'canonicalizationMethod' => null,
                    'includes' => null,
                ]],
                'contentTimestampParameters' => [
                    'digestAlgorithm' => $timestampData['digestAlgorithm'] ?? 'SHA512',
                    'canonicalizationMethod' => 'http://www.w3.org/2001/10/xml-exc-c14n#',
                    'timestampContainerForm' => $timestampData['timestampContainerForm'] ?? 'ASiC_S',
                ],
                'signatureTimestampParameters' => [
                    'digestAlgorithm' => 'SHA512',
                    'canonicalizationMethod' => 'http://www.w3.org/2001/10/xml-exc-c14n#',
                    'timestampContainerForm' => null,
                ],
                'archiveTimestampParameters' => [
                    'digestAlgorithm' => 'SHA512',
                    'canonicalizationMethod' => 'http://www.w3.org/2001/10/xml-exc-c14n#',
                    'timestampContainerForm' => null,
                ],
                'generateTBSWithoutCertificate' => false,
                'imageParameters' => null,
                'signatureIdToCounterSign' => null,
                'blevelParams' => [
                    'trustAnchorBPPolicy' => true,
                    'signingDate' => ($this->clock)(),
                    'claimedSignerRoles' => null,
                    'signedAssertions' => null,
                    'policyId' => null,
                    'policyQualifier' => null,
                    'policyDescription' => null,
                    'policyDigestAlgorithm' => null,
                    'policyDigestValue' => null,
                    'policySpuri' => null,
                    'commitmentTypeIndications' => null,
                    'signerLocationPostalAddress' => [],
                    'signerLocationPostalCode' => null,
                    'signerLocationLocality' => null,
                    'signerLocationStateOrProvince' => null,
                    'signerLocationCountry' => null,
                    'signerLocationStreet' => null,
                ],
            ],
            'toSignDocument' => [
                'bytes' => base64_encode($document),
                'digestAlgorithm' => null,
                'name' => 'RemoteDocument',
            ],
        ];
    }

    private function loadCertificateData(): void {
        if ($this->certificateProvider === null || $this->certificate !== '') {
            return;
        }
        $certificateData = $this->certificateProvider->certificateData();
        if ($certificateData['certificate'] === '') {
            throw new SigningException('DSS signing certificate is missing.');
        }
        $this->certificate = $certificateData['certificate'];
        $this->certificateChain = $certificateData['chain'];
    }

    /** @return array<string, mixed> */
    private function timestamp(string $document): array {
        if ($this->timestampProvider !== null) {
            return $this->timestampProvider->timestamp($document);
        }

        $response = $this->httpClient->postJson($this->url('/one-document/timestampDocument'), [
            'timestampParameters' => [
                'digestAlgorithm' => 'SHA512',
                'canonicalizationMethod' => 'http://www.w3.org/2001/10/xml-exc-c14n#',
                'timestampContainerForm' => 'ASiC_S',
            ],
            'toTimestampDocument' => ['bytes' => base64_encode($document)],
        ]);
        $encodedTimestamp = $response['bytes'] ?? null;
        $timestamp = is_string($encodedTimestamp) ? base64_decode($encodedTimestamp, true) : false;
        if ($timestamp === false || $timestamp === '') {
            throw new SigningException('DSS returned an invalid timestamp token.');
        }
        $response['bytes'] = $timestamp;

        return $response;
    }

    /** @param array<string, mixed> $response */
    private function decodeBytes(array $response, string $message): string {
        $encoded = $response['bytes'] ?? null;
        $decoded = is_string($encoded) ? base64_decode($encoded, true) : false;
        if ($decoded === false || $decoded === '') {
            throw new SigningException($message);
        }

        return $decoded;
    }

    private function url(string $path): string {
        return rtrim($this->serviceUrl, '/') . $path;
    }

    private function encryptionAlgorithm(): string {
        return match ($this->signingProvider->signatureAlgorithm()) {
            'RSA_SHA256' => 'RSA',
            'ECDSA_SHA256' => 'ECDSA',
            default => throw new SigningException('DSS signing algorithm is not supported.'),
        };
    }
}
