<?php

declare(strict_types=1);

namespace IsyThl\Signing;

interface TimestampProviderInterface {

    /**
     * Returns the RFC 3161 timestamp token as raw DER bytes.
     *
     * @return array{bytes: string, digestAlgorithm?: string, timestampContainerForm?: string|null}
     */
    public function timestamp(string $document): array;
}
