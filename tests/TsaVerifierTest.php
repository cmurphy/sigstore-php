<?php

namespace Sigstore\Tests;

use PHPUnit\Framework\TestCase;
use Sigstore\TsaVerifier;
use Dev\Sigstore\Trustroot\V1\TrustedRoot;
use Dev\Sigstore\Trustroot\V1\CertificateAuthority;
use Dev\Sigstore\Common\V1\X509CertificateChain;
use Dev\Sigstore\Common\V1\X509Certificate;
use Dev\Sigstore\Common\V1\TimeRange;
use Google\Protobuf\Timestamp;

class TsaVerifierTest extends TestCase
{
    private string $tsaTokenDer;
    private string $artifactSignatureBytes;
    private TrustedRoot $trustedRoot;

    protected function setUp(): void
    {
        $this->tsaTokenDer = file_get_contents(__DIR__ . '/assets/tsa_token.der');
        $this->artifactSignatureBytes = file_get_contents(__DIR__ . '/assets/artifact_signature.bin');
        
        $leafPem = file_get_contents(__DIR__ . '/assets/tsa_leaf.pem');
        $leafDer = base64_decode(str_replace(["-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", "\n", "\r"], "", $leafPem));
        
        $caPem = file_get_contents(__DIR__ . '/assets/tsa_ca.pem');
        $caDer = base64_decode(str_replace(["-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", "\n", "\r"], "", $caPem));
        
        $leafCert = new X509Certificate();
        $leafCert->setRawBytes($leafDer);
        
        $caCert = new X509Certificate();
        $caCert->setRawBytes($caDer);

        $chain = new X509CertificateChain();
        $chain->setCertificates([$leafCert, $caCert]);
        
        $ta = new CertificateAuthority();
        $ta->setCertChain($chain);
        
        $this->trustedRoot = new TrustedRoot();
        $this->trustedRoot->setTimestampAuthorities([$ta]);
    }

    public function testVerifyValidTsa()
    {
        // Signing time extracted from openssl ts -reply -text for this specific token
        $signingTime = new \DateTime("2025-06-12 12:02:20 UTC");
        
        $result = TsaVerifier::verify($this->tsaTokenDer, $this->artifactSignatureBytes, $this->trustedRoot, $signingTime);
        $this->assertTrue($result, 'TSA verification should pass for a valid token.');
    }
    
    public function testVerifyFailsWithInvalidSignature()
    {
        $signingTime = new \DateTime("2025-06-12 12:02:20 UTC");
        $invalidSignature = "completely_invalid_signature_bytes";
        
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('TSA Verification failed against all trusted authorities');
        
        TsaVerifier::verify($this->tsaTokenDer, $invalidSignature, $this->trustedRoot, $signingTime);
    }
    
    public function testVerifyFailsWhenTsaCertNotYetValid()
    {
        $signingTime = new \DateTime("2025-06-12 12:02:20 UTC");
        
        $timestamp = new Timestamp();
        $timestamp->setSeconds(1893456000); // Jan 1, 2030
        
        $timeRange = new TimeRange();
        $timeRange->setStart($timestamp);
        
        $ta = $this->trustedRoot->getTimestampAuthorities()[0];
        $ta->setValidFor($timeRange);
        
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('TSA certificate is not yet valid at signing time');
        
        TsaVerifier::verify($this->tsaTokenDer, $this->artifactSignatureBytes, $this->trustedRoot, $signingTime);
    }
    
    public function testVerifyFailsWhenTsaCertExpired()
    {
        $signingTime = new \DateTime("2025-06-12 12:02:20 UTC");
        
        $timestamp = new Timestamp();
        $timestamp->setSeconds(1577836800); // Jan 1, 2020
        
        $timeRange = new TimeRange();
        $timeRange->setEnd($timestamp);
        
        $ta = $this->trustedRoot->getTimestampAuthorities()[0];
        $ta->setValidFor($timeRange);
        
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('TSA certificate has expired at signing time');
        
        TsaVerifier::verify($this->tsaTokenDer, $this->artifactSignatureBytes, $this->trustedRoot, $signingTime);
    }
}
