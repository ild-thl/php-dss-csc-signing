<?php

declare(strict_types=1);

namespace IsyThl\Signing\Csc;

use IsyThl\Signing\Exception\SigningException;
use IsyThl\Signing\Tsp\Der;

final class CscTimestampTokenNormalizer {

    public function normalize(string $encodedOrDer): string {
        $candidate = $encodedOrDer;
        for ($depth = 0; $depth < 3; $depth++) {
            if ($this->isCmsTimestampToken($candidate)) {
                return $candidate;
            }
            $token = $this->timestampTokenFromResponse($candidate);
            if ($token !== null) {
                return $token;
            }
            $decoded = base64_decode($candidate, true);
            if ($decoded === false || $decoded === $candidate) {
                break;
            }
            $candidate = $decoded;
        }

        throw new SigningException('CSC returned an invalid timestamp token.');
    }

    private function isCmsTimestampToken(string $der): bool {
        try {
            [$tag, $content, $end] = Der::read($der, 0);
            if ($tag !== 0x30 || $end !== strlen($der)) {
                return false;
            }
            [$oidTag, $oid, $offset] = Der::read($content, 0);
            if ($oidTag !== 0x06 || $oid !== hex2bin('2a864886f70d010702')) {
                return false;
            }
            [$explicitTag, $explicit, $next] = Der::read($content, $offset);
            if ($explicitTag !== 0xa0 || $next !== strlen($content)) {
                return false;
            }
            [$signedDataTag, , $explicitEnd] = Der::read($explicit, 0);

            return $signedDataTag === 0x30 && $explicitEnd === strlen($explicit);
        } catch (\Throwable) {
            return false;
        }
    }

    private function timestampTokenFromResponse(string $der): ?string {
        try {
            [$tag, $content, $end] = Der::read($der, 0);
            if ($tag !== 0x30 || $end !== strlen($der)) {
                return null;
            }
            [$statusTag, $statusInfo, $offset] = Der::read($content, 0);
            if ($statusTag !== 0x30) {
                return null;
            }
            [$statusIntegerTag, $status, $statusEnd] = Der::read($statusInfo, 0);
            if ($statusIntegerTag !== 0x02 || ! in_array($status, ["\x00", "\x01"], true)) {
                return null;
            }
            if ($statusEnd < strlen($statusInfo)) {
                [, , $statusEnd] = Der::read($statusInfo, $statusEnd);
            }
            if ($statusEnd !== strlen($statusInfo)) {
                return null;
            }
            [$tokenTag, , $tokenEnd] = Der::read($content, $offset);
            $token = substr($content, $offset, $tokenEnd - $offset);

            return $tokenEnd === strlen($content) && $tokenTag === 0x30 && $this->isCmsTimestampToken($token)
                ? $token
                : null;
        } catch (\Throwable) {
            return null;
        }
    }
}
