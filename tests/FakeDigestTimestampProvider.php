<?php

declare(strict_types=1);

namespace IsyThl\Signing\Tests;

use IsyThl\Signing\DigestTimestampProviderInterface;

final class FakeDigestTimestampProvider implements DigestTimestampProviderInterface {

    /** @var array{string, string}|null */
    public ?array $received = null;

    public function __construct(private string $token) {
    }

    public function timestampDigest(string $digest, string $digestAlgorithmOid): array {
        $this->received = [$digest, $digestAlgorithmOid];

        return [
            'bytes' => $this->token,
            'digestAlgorithm' => $digestAlgorithmOid,
            'timestampContainerForm' => null,
        ];
    }
}
