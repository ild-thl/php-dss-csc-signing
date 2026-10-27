<?php

declare(strict_types=1);

namespace IsyThl\Signing;

interface DigestTimestampProviderInterface {

    /** @return array{bytes: string, digestAlgorithm: string, timestampContainerForm: string|null} */
    public function timestampDigest(string $digest, string $digestAlgorithmOid): array;
}
