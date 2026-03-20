<?php

namespace Sigstore\Tests;

use PHPUnit\Framework\TestCase;
use Sigstore\SctVerifier;
use Dev\Sigstore\Trustroot\V1\TrustedRoot;
use Dev\Sigstore\Trustroot\V1\TransparencyLogInstance;
use Dev\Sigstore\Common\V1\PublicKey;
use Dev\Sigstore\Common\V1\TimeRange;
use Google\Protobuf\Timestamp;

class SctVerifierTest extends TestCase
{
    private string $leafCertDer;
    private string $issuerCertDer;
    private TrustedRoot $trustedRoot;

    protected function setUp(): void
    {
        $leafPem = file_get_contents(__DIR__ . '/assets/leaf.pem');
        $this->leafCertDer = base64_decode(str_replace(["-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", "\n", "\r"], "", $leafPem));
        
        $issuerPem = file_get_contents(__DIR__ . '/assets/issuer.pem');
        $this->issuerCertDer = base64_decode(str_replace(["-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", "\n", "\r"], "", $issuerPem));
        
        $ctKeyPem = file_get_contents(__DIR__ . '/assets/ctlog_key.pem');
        $ctKeyDer = base64_decode(str_replace(["-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----", "\n", "\r"], "", $ctKeyPem));
        
        $publicKey = new PublicKey();
        $publicKey->setRawBytes($ctKeyDer);
        
        $ctlog = new TransparencyLogInstance();
        $ctlog->setPublicKey($publicKey);
        
        $this->trustedRoot = new TrustedRoot();
        $this->trustedRoot->setCtlogs([$ctlog]);
    }

    public function testVerifyValidSct()
    {
        // This should successfully verify without throwing an exception.
        SctVerifier::verify($this->leafCertDer, $this->issuerCertDer, $this->trustedRoot);
        
        // PHPUnit expects at least one assertion per test.
        $this->assertTrue(true, 'SCT verification passed successfully.');
    }
    
    public function testVerifyFailsWithIncorrectIssuer()
    {
        // Supplying the wrong issuer certificate will alter the IssuerKeyId in the 
        // digitally signed struct, causing the ECDSA signature verification to fail.
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('SCT signature verification failed');
        
        // Pass the leaf cert as the issuer cert to force a mismatch.
        @SctVerifier::verify($this->leafCertDer, $this->leafCertDer, $this->trustedRoot);
    }
    
    public function testVerifyFailsWhenCtLogKeyIsMissing()
    {
        // Create an empty TrustedRoot with no CT Logs.
        $emptyRoot = new TrustedRoot();
        
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('CT Log key not found for log ID');
        
        SctVerifier::verify($this->leafCertDer, $this->issuerCertDer, $emptyRoot);
    }

    public function testVerifyFailsWhenMissingSctExtension()
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Certificate does not contain an SCT extension');
        
        // The issuer cert does not have an SCT extension embedded, so passing it as the leaf cert will trigger the missing check.
        SctVerifier::verify($this->issuerCertDer, $this->issuerCertDer, $this->trustedRoot);
    }

    public function testVerifyFailsWhenSctTimestampBeforeValidityStart()
    {
        // The embedded SCT timestamp is around July 2025.
        // We set the Validity Start of the CT Log key to 2030.
        $timestamp = new Timestamp();
        $timestamp->setSeconds(1893456000); // Jan 1, 2030
        
        $timeRange = new TimeRange();
        $timeRange->setStart($timestamp);
        
        $ctlog = $this->trustedRoot->getCtlogs()[0];
        $ctlog->getPublicKey()->setValidFor($timeRange);
        
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('SCT timestamp is before CT log key validity start');
        
        SctVerifier::verify($this->leafCertDer, $this->issuerCertDer, $this->trustedRoot);
    }
    
    public function testVerifyFailsWhenSctTimestampAfterValidityEnd()
    {
        // The embedded SCT timestamp is around July 2025.
        // We set the Validity End of the CT Log key to 2020.
        $timestamp = new Timestamp();
        $timestamp->setSeconds(1577836800); // Jan 1, 2020
        
        $timeRange = new TimeRange();
        $timeRange->setEnd($timestamp);
        
        $ctlog = $this->trustedRoot->getCtlogs()[0];
        $ctlog->getPublicKey()->setValidFor($timeRange);
        
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('SCT timestamp is after CT log key validity end');
        
        SctVerifier::verify($this->leafCertDer, $this->issuerCertDer, $this->trustedRoot);
    }

    public function testVerifyFailsWithThresholdTwoAndOneValidSct()
    {
        // The fixture leaf certificate only has 1 embedded SCT.
        // If we require a threshold of 2, it should fail.
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Failed to find enough valid SCTs (required: 2, found: 1)');
        
        SctVerifier::verify($this->leafCertDer, $this->issuerCertDer, $this->trustedRoot, 2);
    }
}
