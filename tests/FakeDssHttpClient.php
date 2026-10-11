<?php

declare(strict_types=1);

namespace IsyThl\Signing\Tests;

use IsyThl\Signing\Http\HttpClientInterface;

final class FakeDssHttpClient implements HttpClientInterface {

    public array $dataToSignDocument = [];

    public array $signature = [];

    public array $certificateChain = [];

    public array $contentTimestamps = [];

    public string $encryptionAlgorithm = '';

    public string $jwsSerializationType = '';

    public bool $base64UrlEncodedEtsiUComponents = false;

    public bool $returnEmptyDataToSign = false;

    public bool $returnEmptySignedDocument = false;

    public int $signingDate = 0;

    public function __construct(private array &$calls) {
    }

    public function postJson(
        string $url,
        array $data,
        array $headers = [],
        array $tlsOptions = []
    ): array {
        if (str_ends_with($url, '/timestampDocument')) {
            $this->calls[] = 'dss-timestamp';

            return ['bytes' => base64_encode('timestamp-token')];
        }
        if (str_ends_with($url, '/getDataToSign')) {
            $this->calls[] = 'getDataToSign';
            $this->dataToSignDocument = json_decode(
                base64_decode($data['toSignDocument']['bytes'], true),
                true
            );
            $this->certificateChain = array_column(
                $data['parameters']['certificateChain'],
                'encodedCertificate'
            );
            $this->contentTimestamps = $data['parameters']['contentTimestamps'];
            $this->encryptionAlgorithm = $data['parameters']['encryptionAlgorithm'];
            $this->jwsSerializationType = $data['parameters']['jwsSerializationType'];
            $this->base64UrlEncodedEtsiUComponents =
                $data['parameters']['base64UrlEncodedEtsiUComponents'];
            $this->signingDate = $data['parameters']['blevelParams']['signingDate'];

            return [
                'bytes' => $this->returnEmptyDataToSign
                    ? ''
                    : base64_encode('dss-data-to-sign'),
            ];
        }
        $this->calls[] = 'signDocument';
        $this->signature = $data['signatureValue'];

        return [
            'bytes' => $this->returnEmptySignedDocument
                ? ''
                : base64_encode('{"signed":true}'),
        ];
    }

    public function postForm(
        string $url,
        array $data,
        array $headers = [],
        array $tlsOptions = []
    ): array {
        throw new \LogicException('form transport is not used');
    }
}
