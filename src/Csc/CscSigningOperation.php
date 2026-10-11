<?php

declare(strict_types=1);

namespace IsyThl\Signing\Csc;

final class CscSigningOperation {

    public function __construct(
        public readonly string $requestId,
        public readonly string $accessToken
    ) {
    }
}
