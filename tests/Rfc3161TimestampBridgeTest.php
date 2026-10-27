<?php

declare(strict_types=1);

namespace IsyThl\Signing\Tests;

use IsyThl\Signing\Tsp\Der;
use IsyThl\Signing\Tsp\Rfc3161TimestampBridge;
use PHPUnit\Framework\TestCase;

final class Rfc3161TimestampBridgeTest extends TestCase {

    public function test_wraps_provider_token_in_successful_timestamp_response(): void {
        $token = hex2bin('300f06092a864886f70d010702a0023000');
        $provider = new FakeDigestTimestampProvider($token);
        $bridge = new Rfc3161TimestampBridge($provider);
        $digest = hash('sha256', 'content', true);

        $response = $bridge->respond($this->request('2.16.840.1.101.3.4.2.1', $digest));

        $this->assertSame([$digest, '2.16.840.1.101.3.4.2.1'], $provider->received);
        $this->assertSame(Der::encode(0x30, Der::encode(0x30, Der::encode(0x02, "\x00")) . $token), $response);
    }

    public function test_rejects_requests_with_nonce(): void {
        $bridge = new Rfc3161TimestampBridge(new FakeDigestTimestampProvider('unused'));
        $request = $this->request('2.16.840.1.101.3.4.2.1', hash('sha256', 'content', true), true);

        $response = $bridge->respond($request);

        $this->assertSame(
            Der::encode(
                0x30,
                Der::encode(
                    0x30,
                    Der::encode(0x02, "\x02")
                        . Der::encode(0x30, Der::encode(0x0c, 'Timestamp request rejected'))
                )
            ),
            $response
        );
    }

    public function test_rejects_unknown_digest_algorithm(): void {
        $bridge = new Rfc3161TimestampBridge(new FakeDigestTimestampProvider('unused'));
        $request = $this->request('1.2.3.4', hash('sha256', 'content', true));

        [, $responseContent] = Der::read($bridge->respond($request), 0);
        [, $statusInfo] = Der::read($responseContent, 0);
        [, $status] = Der::read($statusInfo, 0);
        $this->assertSame("\x02", $status);
    }

    private function request(string $oid, string $digest, bool $includeNonce = false): string {
        $algorithm = Der::encode(0x30, $this->encodeOid($oid) . Der::encode(0x05, ''));
        $imprint = Der::encode(0x30, $algorithm . Der::encode(0x04, $digest));
        $content = Der::encode(0x02, "\x01") . $imprint;
        if ($includeNonce) {
            $content .= Der::encode(0x02, "\x01");
        }
        $content .= Der::encode(0x01, "\xff");

        return Der::encode(0x30, $content);
    }

    private function encodeOid(string $oid): string {
        $arcs = array_map('intval', explode('.', $oid));
        $values = [$arcs[0] * 40 + $arcs[1], ...array_slice($arcs, 2)];
        $encoded = '';
        foreach ($values as $value) {
            $encodedArc = chr($value & 0x7f);
            while (($value >>= 7) > 0) {
                $encodedArc = chr(($value & 0x7f) | 0x80) . $encodedArc;
            }
            $encoded .= $encodedArc;
        }

        return Der::encode(0x06, $encoded);
    }
}
