<?php

declare(strict_types=1);

namespace IsyThl\Signing\Dss;

use IsyThl\Signing\Csc\CscSigningOperation;

final class DssSigningOperation {

    /**
     * @param  array<string, mixed>  $requestBody
     */
    public function __construct(
        public readonly array $requestBody,
        public readonly CscSigningOperation $cscOperation
    ) {
    }
}
