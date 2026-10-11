<?php

declare(strict_types=1);

namespace IsyThl\Signing\Csc;

interface AsyncSigningProviderInterface {

    public function startSigning(string $data): CscSigningOperation;

    /** Returns null while the signature is not ready. */
    public function pollSigning(CscSigningOperation $operation): ?string;

    public function revokeSigningOperation(CscSigningOperation $operation): void;
}
