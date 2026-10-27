<?php

declare(strict_types=1);

namespace IsyThl\Signing\Tests;

use IsyThl\Signing\Dss\DssValidator;
use IsyThl\Signing\Exception\ValidationException;
use IsyThl\Signing\Http\HttpClientInterface;
use PHPUnit\Framework\TestCase;

final class DssValidatorTest extends TestCase {

    public function test_dss_validation_url_must_use_https(): void {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('DSS validation endpoint is not configured.');
        new DssValidator(new FakeValidationHttpClient([]), 'http://dss.example');
    }

    public function test_insecure_dss_validation_requires_explicit_opt_in(): void {
        new DssValidator(new FakeValidationHttpClient([]), 'http://dss.example', '/validation', true);

        $this->addToAssertionCount(1);
    }

    public function test_validation_requires_qualification_evidence(): void {
        $client = new FakeValidationHttpClient([
            'valid' => true,
            'qualified' => true,
            'certificateTrusted' => true,
            'revocationValid' => true,
            'timestampValid' => true,
            'trustedListValid' => true,
            'certificatePurposeValid' => true,
            'signingTimeQualified' => true,
            'evidenceIdentifiers' => ['sig-1', 'ts-1'],
        ]);
        $validator = new DssValidator($client, 'https://dss.example');

        $result = $validator->validate('{"signed":true}');

        $this->assertTrue($result->isValid());
        $this->assertTrue($result->isQualified());
        $this->assertSame(['sig-1', 'ts-1'], $result->evidenceIdentifiers());
        $this->assertSame('eyJzaWduZWQiOnRydWV9', $client->documentBytes);
    }

    public function test_cryptographic_validity_without_qualification_fails(): void {
        $client = new FakeValidationHttpClient([
            'valid' => true,
            'qualified' => false,
            'certificateTrusted' => true,
            'revocationValid' => true,
            'timestampValid' => true,
            'trustedListValid' => true,
            'certificatePurposeValid' => true,
            'signingTimeQualified' => true,
        ]);
        $validator = new DssValidator($client, 'https://dss.example');

        $this->expectException(ValidationException::class);
        $validator->validate('{"signed":true}');
    }

    public function test_malformed_validation_evidence_fails(): void {
        $client = new FakeValidationHttpClient([
            'valid' => true,
            'qualified' => true,
            'certificateTrusted' => true,
            'revocationValid' => true,
            'timestampValid' => true,
            'trustedListValid' => true,
            'certificatePurposeValid' => true,
            'signingTimeQualified' => true,
            'evidenceIdentifiers' => ['sig-1', 42],
        ]);
        $validator = new DssValidator($client, 'https://dss.example');

        $this->expectException(ValidationException::class);
        $validator->validate('{"signed":true}');
    }

    public function test_invalid_certificate_purpose_fails_qualified_policy(): void {
        $client = new FakeValidationHttpClient([
            'valid' => true,
            'qualified' => true,
            'certificateTrusted' => true,
            'revocationValid' => true,
            'timestampValid' => true,
            'trustedListValid' => true,
            'certificatePurposeValid' => false,
            'signingTimeQualified' => true,
        ]);
        $validator = new DssValidator($client, 'https://dss.example');

        $this->expectException(ValidationException::class);
        $validator->validate('{"signed":true}');
    }

    public function test_empty_validation_evidence_fails(): void {
        $client = new FakeValidationHttpClient([
            'valid' => true,
            'qualified' => true,
            'certificateTrusted' => true,
            'revocationValid' => true,
            'timestampValid' => true,
            'trustedListValid' => true,
            'certificatePurposeValid' => true,
            'signingTimeQualified' => true,
            'evidenceIdentifiers' => [],
        ]);
        $validator = new DssValidator($client, 'https://dss.example');

        $this->expectException(ValidationException::class);
        $validator->validate('{"signed":true}');
    }

    public function test_whitespace_validation_evidence_fails(): void {
        $client = new FakeValidationHttpClient([
            'valid' => true,
            'qualified' => true,
            'certificateTrusted' => true,
            'revocationValid' => true,
            'timestampValid' => true,
            'trustedListValid' => true,
            'certificatePurposeValid' => true,
            'signingTimeQualified' => true,
            'evidenceIdentifiers' => ['  '],
        ]);
        $validator = new DssValidator($client, 'https://dss.example');

        $this->expectException(ValidationException::class);
        $validator->validate('{"signed":true}');
    }

    public function test_dss_65_report_dto_maps_to_strict_validation_result(): void {
        $client = new FakeValidationHttpClient($this->dss65Report());
        $validator = new DssValidator($client, 'https://dss.example');

        $result = $validator->validate('{"signed":true}');

        $this->assertTrue($result->isValid());
        $this->assertTrue($result->isQualified());
        $this->assertSame(
            ['signature-1', 'certificate-1', 'timestamp-1', 'tsl-1', 'lotl-1'],
            $result->evidenceIdentifiers()
        );
    }

    public function test_nonqualified_mode_allows_only_qualification_and_trust_failures(): void {
        $report = $this->dss65Report();
        $report['DiagnosticData']['Certificate'][0]['Trusted']['value'] = false;
        unset($report['DiagnosticData']['Certificate'][0]['TrustServiceProvider']);
        $report['DiagnosticData']['TrustedList'] = [];
        $qualification = &$report['DetailedReport']['SignatureOrTimestampOrEvidenceRecord'][0]
            ['Signature']['ValidationSignatureQualification'];
        $qualification['Conclusion']['Indication'] = 'FAILED';
        $qualification['SignatureQualification'] = 'N/A';
        $qualification['ValidationCertificateQualification'] = [];
        $client = new FakeValidationHttpClient($report);
        $validator = new DssValidator($client, 'https://dss.example', allowUnqualified: true);

        $result = $validator->validate('{"signed":true}');

        $this->assertTrue($result->isValid());
        $this->assertFalse($result->isQualified());
        $this->assertFalse($result->report()['certificateTrusted']);
        $this->assertTrue($result->report()['revocationValid']);
        $this->assertTrue($result->report()['timestampValid']);
        $this->assertFalse($result->report()['trustedListValid']);
        $this->assertFalse($result->report()['certificatePurposeValid']);
        $this->assertFalse($result->report()['signingTimeQualified']);
    }

    public function test_nonqualified_mode_still_rejects_invalid_signatures(): void {
        $report = $this->dss65Report();
        $report['DetailedReport']['SignatureOrTimestampOrEvidenceRecord'][0]
            ['Signature']['Conclusion']['Indication'] = 'FAILED';
        $client = new FakeValidationHttpClient($report);
        $validator = new DssValidator($client, 'https://dss.example', allowUnqualified: true);

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Failed checks: valid.');
        $validator->validate('{"signed":true}');
    }

    public function test_nonqualified_mode_still_rejects_bad_revocation(): void {
        $report = $this->dss65Report();
        $report['DiagnosticData']['Certificate'][0]['CertificateRevocation']['Status'] = 'UNKNOWN';
        $client = new FakeValidationHttpClient($report);
        $validator = new DssValidator($client, 'https://dss.example', allowUnqualified: true);

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Failed checks: revocationValid.');
        $validator->validate('{"signed":true}');
    }

    public function test_nonqualified_mode_still_rejects_missing_timestamps(): void {
        $report = $this->dss65Report();
        $report['DiagnosticData']['Timestamp'] = [];
        $client = new FakeValidationHttpClient($report);
        $validator = new DssValidator($client, 'https://dss.example', allowUnqualified: true);

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Failed checks: timestampValid.');
        $validator->validate('{"signed":true}');
    }

    public function test_dss_65_report_without_timestamp_evidence_fails_closed(): void {
        $report = $this->dss65Report();
        $report['DiagnosticData']['Timestamp'] = [];
        $client = new FakeValidationHttpClient($report);
        $validator = new DssValidator($client, 'https://dss.example');

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage(
            'DSS validation did not meet the qualified issuance policy. Failed checks: timestampValid.'
        );
        $validator->validate('{"signed":true}');
    }

    public function test_dss_65_report_with_unrelated_trusted_list_fails_closed(): void {
        $report = $this->dss65Report();
        $report['DiagnosticData']['Certificate'][0]['TrustServiceProvider']['TL']['Id'] = 'unrelated-tsl';
        $client = new FakeValidationHttpClient($report);
        $validator = new DssValidator($client, 'https://dss.example');

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage(
            'DSS validation did not meet the qualified issuance policy. Failed checks: trustedListValid.'
        );
        $validator->validate('{"signed":true}');
    }

    private function dss65Report(): array {
        return [
            'DiagnosticData' => [
                'Signature' => [
                    ['SigningCertificate' => ['Certificate' => 'certificate-1']],
                ],
                'Certificate' => [
                    [
                        'Id' => 'certificate-1',
                        'Trusted' => ['value' => true],
                        'Source' => 'SIGNATURE',
                        'CertificateRevocation' => ['Status' => 'GOOD'],
                        'TrustServiceProvider' => [
                            'TL' => [
                                'Id' => 'tsl-1',
                                'WellSigned' => true,
                                'Lotl' => false,
                                'Parent' => ['Id' => 'lotl-1', 'WellSigned' => true, 'Lotl' => true],
                            ],
                            'LOTL' => ['Id' => 'lotl-1', 'WellSigned' => true, 'Lotl' => true],
                        ],
                    ],
                ],
                'Timestamp' => [
                    [
                        'Id' => 'timestamp-1',
                        'BasicSignature' => ['SignatureIntact' => true, 'SignatureValid' => true],
                    ],
                ],
                'TrustedList' => [
                    ['Id' => 'tsl-1', 'WellSigned' => true, 'Lotl' => false],
                    ['Id' => 'lotl-1', 'WellSigned' => true, 'Lotl' => true],
                ],
            ],
            'SimpleReport' => [
                'SignatureOrTimestampOrEvidenceRecord' => [
                    ['Signature' => [
                        'Id' => 'signature-1',
                        'Indication' => 'TOTAL_PASSED',
                        'SignatureFormat' => 'JAdES-BASELINE-LTA',
                    ]],
                ],
            ],
            'DetailedReport' => [
                'SignatureOrTimestampOrEvidenceRecord' => [
                    ['Signature' => [
                        'Id' => 'signature-1',
                        'Conclusion' => ['Indication' => 'TOTAL_PASSED'],
                        'ValidationProcessBasicSignature' => [
                            'Conclusion' => ['Indication' => 'TOTAL_PASSED'],
                        ],
                        'Timestamp' => [
                            [
                                'Id' => 'timestamp-1',
                                'Conclusion' => ['Indication' => 'TOTAL_PASSED'],
                            ],
                        ],
                        'ValidationSignatureQualification' => [
                            'Conclusion' => ['Indication' => 'TOTAL_PASSED'],
                            'SignatureQualification' => 'QESEAL',
                            'ValidationCertificateQualification' => [
                                [
                                    'Id' => 'certificate-1',
                                    'ValidationTime' => 'BEST_SIGNATURE_TIME',
                                    'CertificateQualification' => 'QCERT_FOR_ESEAL_QSCD',
                                    'Conclusion' => ['Indication' => 'TOTAL_PASSED'],
                                ],
                            ],
                        ],
                    ]],
                ],
            ],
        ];
    }
}
