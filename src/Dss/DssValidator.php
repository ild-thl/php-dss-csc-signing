<?php

declare(strict_types=1);

namespace IsyThl\Signing\Dss;

use IsyThl\Signing\Exception\ValidationException;
use IsyThl\Signing\DocumentValidatorInterface;
use IsyThl\Signing\Http\HttpClientInterface;
use IsyThl\Signing\ValidationResult;

final class DssValidator implements DocumentValidatorInterface {

    public function __construct(
        private HttpClientInterface $httpClient,
        private string $serviceUrl,
        private string $validationPath = '/validation/validateDocument',
        private bool $allowInsecureTransport = false,
        private bool $allowUnqualified = false
    ) {
        if (
            $serviceUrl === ''
            || (!$this->allowInsecureTransport && parse_url($serviceUrl, PHP_URL_SCHEME) !== 'https')
            || $validationPath === ''
        ) {
            throw new ValidationException('DSS validation endpoint is not configured.');
        }
    }

    public function validate(string $signedDocument): ValidationResult {
        if ($signedDocument === '') {
            throw new ValidationException('Signed document must not be empty.');
        }
        $report = $this->httpClient->postJson(
            rtrim($this->serviceUrl, '/') . $this->validationPath,
            ['signedDocument' => ['bytes' => base64_encode($signedDocument)]]
        );
        if ($this->field($report, 'simpleReport') !== null) {
            $report = array_merge($report, $this->mapDssReport($report));
        }
        foreach (
            [
                'valid', 'qualified', 'certificateTrusted', 'revocationValid', 'timestampValid', 'trustedListValid',
                'certificatePurposeValid', 'signingTimeQualified',
            ] as $field
        ) {
            if (!isset($report[$field]) || !is_bool($report[$field])) {
                throw new ValidationException('DSS validation response is missing: ' . $field, $report);
            }
        }
        $evidence = $report['evidenceIdentifiers'] ?? [];
        if (
            !is_array($evidence)
            || $evidence === []
            || array_filter($evidence, static fn($value): bool => !is_string($value) || trim($value) === '')
        ) {
            throw new ValidationException('DSS validation evidence identifiers are malformed.', $report);
        }
        $result = new ValidationResult(
            $report['valid'],
            $report['qualified'],
            $report,
            array_values($evidence)
        );
        $policyChecks = [
            'valid' => $result->isValid(),
            'qualified' => $result->isQualified(),
            'certificateTrusted' => $report['certificateTrusted'],
            'revocationValid' => $report['revocationValid'],
            'timestampValid' => $report['timestampValid'],
            'trustedListValid' => $report['trustedListValid'],
            'certificatePurposeValid' => $report['certificatePurposeValid'],
            'signingTimeQualified' => $report['signingTimeQualified'],
        ];
        if ($this->allowUnqualified) {
            unset(
                $policyChecks['qualified'],
                $policyChecks['certificateTrusted'],
                $policyChecks['trustedListValid'],
                $policyChecks['certificatePurposeValid'],
                $policyChecks['signingTimeQualified']
            );
        }
        $failedChecks = array_keys(array_filter($policyChecks, static fn(bool $passed): bool => !$passed));
        if ($failedChecks !== []) {
            throw new ValidationException(
                'DSS validation did not meet the qualified issuance policy. Failed checks: '
                . implode(', ', $failedChecks) . '.',
                $report
            );
        }
        return $result;
    }

    /**
     * @param array<array-key, mixed> $report
     * @return array<string, mixed>
     */
    private function mapDssReport(array $report): array {
        $simpleReport = $this->field($report, 'simpleReport');
        $detailedReport = $this->field($report, 'detailedReport');
        $diagnosticData = $this->field($report, 'diagnosticData');
        if (!is_array($simpleReport) || !is_array($detailedReport) || !is_array($diagnosticData)) {
            return [];
        }

        $simpleSignatures = $this->records($simpleReport, 'signatureOrTimestampOrEvidenceRecord', 'Signature');
        $detailedSignatures = $this->records($detailedReport, 'signatureOrTimestampOrEvidenceRecord', 'Signature');
        $diagnosticSignatures = $this->list($this->field($diagnosticData, 'signature'));
        if (count($simpleSignatures) !== 1 || count($detailedSignatures) !== 1 || count($diagnosticSignatures) !== 1) {
            return $this->failedPolicy();
        }

        $simpleSignature = $simpleSignatures[0];
        $detailedSignature = $detailedSignatures[0];
        $diagnosticSignature = $diagnosticSignatures[0];
        $signingCertificateData = $this->field($diagnosticSignature, 'signingCertificate') ?? [];
        $signingCertificate = $this->field($signingCertificateData, 'certificate');
        $certificateId = is_array($signingCertificate)
            ? $this->field($signingCertificate, 'id')
            : (is_string($signingCertificate) ? $signingCertificate : null);
        $certificates = $this->list($this->field($diagnosticData, 'certificate'));
        $certificate = null;
        foreach ($certificates as $candidate) {
            if ($certificateId !== null && $this->field($candidate, 'id') === $certificateId) {
                $certificate = $candidate;
                break;
            }
        }

        $qualification = $this->field($detailedSignature, 'validationSignatureQualification');
        $signatureQualification = is_array($qualification)
            ? $this->stringValue($this->field($qualification, 'signatureQualification'))
            : null;
        $certificateQualifications = is_array($qualification)
            ? $this->list($this->field($qualification, 'validationCertificateQualification'))
            : [];
        $certificateQualification = null;
        foreach ($certificateQualifications as $candidate) {
            if ($certificateId !== null && $this->field($candidate, 'id') === $certificateId) {
                $certificateQualification = $candidate;
                break;
            }
        }
        $certificateQualificationType = is_array($certificateQualification)
            ? $this->stringValue($this->field($certificateQualification, 'certificateQualification'))
            : null;
        $qualificationPassed = is_array($qualification)
            && $this->passed($this->field($this->field($qualification, 'conclusion') ?? [], 'indication'));
        $certificateQualificationPassed = is_array($certificateQualification)
            && $this->passed($this->field($this->field($certificateQualification, 'conclusion') ?? [], 'indication'));
        $qualified = $qualificationPassed && in_array($signatureQualification, ['QESIG', 'QESEAL'], true);
        $purposeMatches = ($signatureQualification === 'QESIG'
                && $certificateQualificationType === 'QCERT_FOR_ESIG_QSCD')
            || ($signatureQualification === 'QESEAL'
                && $certificateQualificationType === 'QCERT_FOR_ESEAL_QSCD');

        $trusted = is_array($certificate) ? $this->field($certificate, 'trusted') : null;
        $certificateTrusted = is_array($trusted) && $this->field($trusted, 'value') === true;
        $revocations = is_array($certificate) ? $this->list($this->field($certificate, 'revocations')) : [];
        if ($revocations === [] && is_array($certificate)) {
            $revocations = $this->list($this->field($certificate, 'certificateRevocation'));
        }
        $revocationValid = $revocations !== [];
        foreach ($revocations as $revocation) {
            $revocationValid = $revocationValid && $this->field($revocation, 'status') === 'GOOD';
        }

        $timestamps = $this->list($this->field($diagnosticData, 'timestamp'));
        $detailedTimestamps = $this->list($this->field($detailedSignature, 'timestamp'));
        $timestampIds = [];
        $timestampValid = $timestamps !== [] && count($timestamps) === count($detailedTimestamps);
        foreach ($timestamps as $timestamp) {
            $timestampId = $this->field($timestamp, 'id');
            $timestampIds[] = $timestampId;
            $timestampSignature = $this->field($timestamp, 'basicSignature');
            $matchingDetailedTimestamp = null;
            foreach ($detailedTimestamps as $candidate) {
                if ($timestampId !== null && $this->field($candidate, 'id') === $timestampId) {
                    $matchingDetailedTimestamp = $candidate;
                    break;
                }
            }
            $timestampValid = $timestampValid
                && is_array($timestampSignature)
                && $this->field($timestampSignature, 'signatureIntact') === true
                && $this->field($timestampSignature, 'signatureValid') === true
                && is_array($matchingDetailedTimestamp)
                && $this->passed($this->field(
                    $this->field($matchingDetailedTimestamp, 'conclusion') ?? [],
                    'indication'
                ));
        }
        $signatureFormat = $this->stringValue($this->field($simpleSignature, 'signatureFormat'));
        $timestampValid = $timestampValid && $signatureFormat !== null
            && str_ends_with(strtoupper($signatureFormat), '-LTA');

        $trustedLists = $this->list($this->field($diagnosticData, 'trustedList'));
        $trustedListIds = [];
        foreach ($trustedLists as $trustedList) {
            $trustedListIds[] = $this->field($trustedList, 'id');
        }
        $trustServiceProviders = is_array($certificate)
            ? $this->list(
                $this->field($certificate, 'trustServiceProviders')
                    ?? $this->field($certificate, 'trustServiceProvider')
            )
            : [];
        $trustedListValid = false;
        foreach ($trustServiceProviders as $trustServiceProvider) {
            $certificateTsl = $this->field($trustServiceProvider, 'tl');
            $certificateLotl = $this->field($trustServiceProvider, 'lotl');
            $trustedListValid = $trustedListValid || (is_array($certificateTsl)
                && is_array($certificateLotl)
                && $this->trustedListChainIsValid($certificateTsl)
                && $this->field($certificateLotl, 'wellSigned') === true
                && $this->field($certificateLotl, 'lotl') === true
                && $this->trustedListIsReported($certificateTsl, $trustedLists)
                && $this->trustedListIsReported($certificateLotl, $trustedLists));
        }

        $signingTimeQualified = is_array($certificateQualification)
            && $this->field($certificateQualification, 'validationTime') === 'BEST_SIGNATURE_TIME'
            && $certificateQualificationPassed;
        $signatureIndication = $this->field($simpleSignature, 'indication');
        $detailedConclusion = $this->field($detailedSignature, 'conclusion');
        $basicSignature = $this->field($detailedSignature, 'validationProcessBasicSignature');
        $valid = $this->passed($signatureIndication)
            && $this->passed($this->field($detailedConclusion ?? [], 'indication'))
            && $this->passed($this->field($this->field($basicSignature ?? [], 'conclusion') ?? [], 'indication'));

        $evidence = array_filter([
            $this->field($simpleSignature, 'id'),
            $certificateId,
            ...$timestampIds,
            ...$trustedListIds,
        ], static fn($value): bool => is_string($value) && trim($value) !== '');

        return [
            'valid' => $valid,
            'qualified' => $qualified,
            'certificateTrusted' => $certificateTrusted,
            'revocationValid' => $revocationValid,
            'timestampValid' => $timestampValid,
            'trustedListValid' => $trustedListValid,
            'certificatePurposeValid' => $purposeMatches && $certificateQualificationPassed,
            'signingTimeQualified' => $signingTimeQualified,
            'evidenceIdentifiers' => array_values($evidence),
        ];
    }

    /** @return array<string, mixed> */
    private function failedPolicy(): array {
        return [
            'valid' => false,
            'qualified' => false,
            'certificateTrusted' => false,
            'revocationValid' => false,
            'timestampValid' => false,
            'trustedListValid' => false,
            'certificatePurposeValid' => false,
            'signingTimeQualified' => false,
            'evidenceIdentifiers' => [],
        ];
    }

    /** @param array<array-key, mixed> $trustedList */
    private function trustedListChainIsValid(array $trustedList, int $depth = 0): bool {
        if ($depth > 8 || $this->field($trustedList, 'wellSigned') !== true) {
            return false;
        }
        if ($this->field($trustedList, 'lotl') === true) {
            return true;
        }
        $parent = $this->field($trustedList, 'parent');
        return is_array($parent) && $this->trustedListChainIsValid($parent, $depth + 1);
    }

    /**
     * @param array<array-key, mixed> $trustedList
     * @param list<array<array-key, mixed>> $reportedLists
     */
    private function trustedListIsReported(array $trustedList, array $reportedLists): bool {
        $id = $this->field($trustedList, 'id');
        if (!is_string($id) || $id === '') {
            return false;
        }
        foreach ($reportedLists as $reportedList) {
            if (
                $this->field($reportedList, 'id') === $id
                && $this->field($reportedList, 'wellSigned') === true
            ) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param array<array-key, mixed> $section
     * @return list<array<array-key, mixed>>
     */
    private function records(array $section, string $collection, string $type): array {
        $records = [];
        foreach ($this->list($this->field($section, $collection)) as $record) {
            $value = $this->field($record, $type);
            if (is_array($value)) {
                $records[] = $value;
            }
        }
        return $records;
    }

    /** @return list<array<array-key, mixed>> */
    private function list(mixed $value): array {
        if (!is_array($value)) {
            return [];
        }
        if (!array_is_list($value)) {
            return [$value];
        }
        return array_values(array_filter($value, 'is_array'));
    }

    /** @param array<array-key, mixed> $object */
    private function field(array $object, string $name): mixed {
        foreach ([$name, ucfirst($name), strtoupper($name)] as $key) {
            if (array_key_exists($key, $object)) {
                return $object[$key];
            }
        }
        return null;
    }

    private function stringValue(mixed $value): ?string {
        if (is_array($value)) {
            $value = $this->field($value, 'value');
        }
        return is_string($value) ? $value : null;
    }

    private function passed(mixed $indication): bool {
        return in_array($this->stringValue($indication), ['TOTAL_PASSED', 'PASSED'], true);
    }
}
