<?php

declare(strict_types=1);

namespace IsyThl\Signing\Tsp;

use IsyThl\Signing\Exception\SigningException;

final class Der {

    /** @return array{int, string, int} tag, content, next offset */
    public static function read(string $der, int $offset): array {
        $start = $offset;
        if ($offset + 2 > strlen($der)) {
            throw new SigningException('Malformed DER value.');
        }
        $tag = ord($der[$offset++]);
        $firstLength = ord($der[$offset++]);
        if (($firstLength & 0x80) === 0) {
            $length = $firstLength;
        } else {
            $lengthBytes = $firstLength & 0x7f;
            if ($lengthBytes === 0 || $lengthBytes > 4 || $offset + $lengthBytes > strlen($der)) {
                throw new SigningException('Malformed DER length.');
            }
            if (ord($der[$offset]) === 0) {
                throw new SigningException('Non-canonical DER length.');
            }
            $length = 0;
            for ($index = 0; $index < $lengthBytes; $index++) {
                $length = ($length << 8) | ord($der[$offset++]);
            }
            if ($length < 128) {
                throw new SigningException('Non-canonical DER length.');
            }
        }
        $end = $offset + $length;
        if ($end > strlen($der) || $end < $start) {
            throw new SigningException('Truncated DER value.');
        }

        return [$tag, substr($der, $offset, $length), $end];
    }

    public static function encode(int $tag, string $content): string {
        $length = strlen($content);
        if ($length < 128) {
            $encodedLength = chr($length);
        } else {
            $bytes = '';
            while ($length > 0) {
                $bytes = chr($length & 0xff) . $bytes;
                $length >>= 8;
            }
            $encodedLength = chr(0x80 | strlen($bytes)) . $bytes;
        }

        return chr($tag) . $encodedLength . $content;
    }
}
