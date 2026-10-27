<?php

declare(strict_types=1);

namespace IsyThl\Signing\Tsp;

use IsyThl\Signing\DigestTimestampProviderInterface;
use IsyThl\Signing\Exception\SigningException;

final class Rfc3161TimestampBridge {

    private const DIGEST_LENGTHS = [
        '2.16.840.1.101.3.4.2.1' => 32,
        '2.16.840.1.101.3.4.2.2' => 48,
        '2.16.840.1.101.3.4.2.3' => 64,
    ];

    public function __construct(private DigestTimestampProviderInterface $provider) {
    }

    public function respond(string $requestDer): string {
        try {
            [$digest, $algorithmOid] = $this->parseRequest($requestDer);
        } catch (SigningException) {
            $statusString = Der::encode(0x30, Der::encode(0x0c, 'Timestamp request rejected'));
            $statusInfo = Der::encode(0x30, Der::encode(0x02, "\x02") . $statusString);

            return Der::encode(0x30, $statusInfo);
        }
        $timestamp = $this->provider->timestampDigest($digest, $algorithmOid);
        $token = $timestamp['bytes'] ?? null;
        if (! is_string($token) || $token === '') {
            throw new SigningException('Timestamp provider returned no token.');
        }
        [$tokenTag, , $tokenEnd] = Der::read($token, 0);
        if ($tokenTag !== 0x30 || $tokenEnd !== strlen($token)) {
            throw new SigningException('Timestamp provider returned malformed token DER.');
        }

        $statusInfo = Der::encode(0x30, Der::encode(0x02, "\x00"));

        return Der::encode(0x30, $statusInfo . $token);
    }

    /** @return array{string, string} digest and algorithm OID */
    private function parseRequest(string $requestDer): array {
        [$requestTag, $requestContent, $requestEnd] = Der::read($requestDer, 0);
        if ($requestTag !== 0x30 || $requestEnd !== strlen($requestDer)) {
            throw new SigningException('Malformed RFC 3161 timestamp request.');
        }
        [$versionTag, $version, $offset] = Der::read($requestContent, 0);
        if ($versionTag !== 0x02 || $version !== "\x01") {
            throw new SigningException('Unsupported RFC 3161 timestamp request version.');
        }
        [$imprintTag, $imprint, $offset] = Der::read($requestContent, $offset);
        if ($imprintTag !== 0x30) {
            throw new SigningException('Malformed RFC 3161 message imprint.');
        }
        [$algorithmTag, $algorithm, $algorithmEnd] = Der::read($imprint, 0);
        if ($algorithmTag !== 0x30) {
            throw new SigningException('Malformed RFC 3161 digest algorithm.');
        }
        [$oidTag, $oidContent, $algorithmOffset] = Der::read($algorithm, 0);
        if ($oidTag !== 0x06) {
            throw new SigningException('RFC 3161 digest algorithm has no OID.');
        }
        if ($algorithmOffset < strlen($algorithm)) {
            [$parametersTag, $parameters, $algorithmOffset] = Der::read($algorithm, $algorithmOffset);
            if ($parametersTag !== 0x05 || $parameters !== '') {
                throw new SigningException('Unsupported RFC 3161 digest algorithm parameters.');
            }
        }
        if ($algorithmOffset !== strlen($algorithm) || $algorithmEnd > strlen($imprint)) {
            throw new SigningException('Malformed RFC 3161 digest algorithm.');
        }
        $algorithmOid = $this->decodeOid($oidContent);
        $digestLength = self::DIGEST_LENGTHS[$algorithmOid] ?? null;
        [$digestTag, $digest, $imprintEnd] = Der::read($imprint, $algorithmEnd);
        if ($digestTag !== 0x04 || $imprintEnd !== strlen($imprint) || strlen($digest) !== $digestLength) {
            throw new SigningException('RFC 3161 message imprint is invalid.');
        }

        while ($offset < strlen($requestContent)) {
            [$optionalTag, $optionalContent, $nextOffset] = Der::read($requestContent, $offset);
            if ($optionalTag === 0x02) {
                throw new SigningException('RFC 3161 nonce is not supported by this timestamp provider.');
            }
            if ($optionalTag === 0x01) {
                if (! in_array($optionalContent, ["\x00", "\xff"], true)) {
                    throw new SigningException('Malformed RFC 3161 certReq value.');
                }
            } elseif (in_array($optionalTag, [0x06, 0xa0], true)) {
                throw new SigningException('RFC 3161 policy and extensions are not supported.');
            } else {
                throw new SigningException('Unsupported RFC 3161 timestamp request field.');
            }
            $offset = $nextOffset;
        }

        return [$digest, $algorithmOid];
    }

    private function decodeOid(string $content): string {
        if ($content === '') {
            throw new SigningException('Malformed RFC 3161 digest algorithm OID.');
        }
        $values = [];
        $value = 0;
        $byte = 0;
        for ($index = 0, $length = strlen($content); $index < $length; $index++) {
            $byte = ord($content[$index]);
            $value = ($value << 7) | ($byte & 0x7f);
            if (($byte & 0x80) === 0) {
                $values[] = $value;
                $value = 0;
            }
        }
        if (($byte & 0x80) !== 0 || $values === []) {
            throw new SigningException('Malformed RFC 3161 digest algorithm OID.');
        }
        $first = array_shift($values);
        $arcs = [min(2, intdiv($first, 40)), $first - min(2, intdiv($first, 40)) * 40, ...$values];

        return implode('.', $arcs);
    }
}
