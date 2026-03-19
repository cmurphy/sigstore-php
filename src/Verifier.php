<?php

namespace Sigstore;

use Dev\Sigstore\Bundle\V1\Bundle;
use Dev\Sigstore\Trustroot\V1\TrustedRoot;
use Google\Protobuf\Internal\Message;
use Io\Intoto\Envelope;
use Io\Intoto\Signature;
use Dev\Sigstore\Bundle\V1\VerificationMaterial;
use Dev\Sigstore\Common\V1\HashAlgorithm;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\PublicKeyLoader;

class Verifier
{
    private const MEDIA_TYPE_BASE = 'application/vnd.dev.sigstore.bundle';
    // Versions supported by THIS library's parsing and verification logic
    private const SUPPORTED_BUNDLE_VERSIONS = ['v0.1', 'v0.2', 'v0.3'];

    private function getBundleVersion(string $mediaType): string
    {
        switch ($mediaType) {
            case self::MEDIA_TYPE_BASE . '+json;version=0.1':
                return 'v0.1';
            case self::MEDIA_TYPE_BASE . '+json;version=0.2':
                return 'v0.2';
            case self::MEDIA_TYPE_BASE . '+json;version=0.3':
                return 'v0.3';
        }

        $prefix = self::MEDIA_TYPE_BASE . '.v';
        $suffix = '+json';

        if (str_starts_with($mediaType, $prefix) && str_ends_with($mediaType, $suffix)) {
            $version = substr($mediaType, strlen($prefix), -strlen($suffix));
            // Basic semver-like check (vX.Y or vX.Y.Z)
            if (preg_match('/^\d+\.\d+(\.\d+)?$/', $version)) {
                return 'v' . $version;
            }
            throw new \RuntimeException("Invalid version format in media type: " . $mediaType);
        }

        throw new \RuntimeException("Unsupported bundle media type: " . $mediaType);
    }

    public function loadBundle(string $bundlePath): Bundle
    {
        if (!file_exists($bundlePath)) {
            throw new \InvalidArgumentException("Bundle file not found: {$bundlePath}");
        }

        $jsonContents = file_get_contents($bundlePath);
        if ($jsonContents === false) {
            throw new \RuntimeException("Could not read bundle file: {$bundlePath}");
        }

        try {
            $data = json_decode($jsonContents, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Exception $e) {
            throw new \RuntimeException("Failed to parse bundle JSON: " . $e->getMessage(), 0, $e);
        }

        $bundle = new Bundle();
        $snakeCaseData = $this->convertKeysToSnakeCase($data);

        // Handle DSSE Envelope separately using original camelCase keys
        if (isset($data['dsseEnvelope'])) {
            $dsseData = $data['dsseEnvelope'];
            unset($snakeCaseData['dsse_envelope']); // Prevent re-processing

            $dsseEnvelope = new Envelope();
            if (isset($dsseData['payload'])) {
                $decodedPayload = base64_decode($dsseData['payload'], true);
                if ($decodedPayload === false) throw new \RuntimeException("Failed to base64 decode DSSE payload");
                $dsseEnvelope->setPayload($decodedPayload);
            }
            if (isset($dsseData['payloadType'])) {
                $dsseEnvelope->setPayloadType($dsseData['payloadType']);
            }
            if (isset($dsseData['signatures']) && is_array($dsseData['signatures'])) {
                foreach ($dsseData['signatures'] as $sigData) {
                    $signature = new Signature();
                    if (isset($sigData['keyid'])) $signature->setKeyid($sigData['keyid']);
                    if (isset($sigData['sig'])) {
                        $decodedSig = base64_decode($sigData['sig'], true);
                        if ($decodedSig === false) throw new \RuntimeException("Failed to base64 decode DSSE signature");
                        $signature->setSig($decodedSig);
                    }
                    $dsseEnvelope->getSignatures()[] = $signature;
                }
            }
            $bundle->setDsseEnvelope($dsseEnvelope);
        }

        // Merge the rest of the bundle data
        try {
            $bundle->mergeFromJsonString(json_encode($snakeCaseData));
        } catch (\Exception $e) {
            // Ignore
        }

        // Validate mediaType and the version derived from it
        $bundleVersion = $this->getBundleVersion($bundle->getMediaType());

        if (!in_array($bundleVersion, self::SUPPORTED_BUNDLE_VERSIONS)) {
            throw new \RuntimeException("Unsupported bundle version derived from media type: " . $bundleVersion);
        }

        return $bundle;
    }

    public function loadTrustedRoot(string $trustedRootPath): TrustedRoot
    {
        // ... (as before)
        if (!file_exists($trustedRootPath)) {
            throw new \InvalidArgumentException("Trusted root file not found: {$trustedRootPath}");
        }
        $jsonContents = file_get_contents($trustedRootPath);
        if ($jsonContents === false) {
            throw new \RuntimeException("Could not read trusted root file: {$trustedRootPath}");
        }
        $trustedRoot = new TrustedRoot();
        try {
            $data = json_decode($jsonContents, true, 512, JSON_THROW_ON_ERROR);
            $snakeCaseData = $this->convertKeysToSnakeCase($data);
            $trustedRoot->mergeFromJsonString(json_encode($snakeCaseData));
        } catch (\Exception $e) {
            throw new \RuntimeException("Failed to parse trusted root JSON: " . $e->getMessage(), 0, $e);
        }
        return $trustedRoot;
    }

    private function convertKeysToSnakeCase(array $data): array
    {
        // ... (as before)
        $result = [];
        foreach ($data as $key => $value) {
            $snakeKey = strtolower(preg_replace('/(?<!^)[A-Z]/', '_$0', $key));
            if (is_array($value)) {
                $result[$snakeKey] = $this->convertKeysToSnakeCase($value);
            } else {
                $result[$snakeKey] = $value;
            }
        }
        return $result;
    }

    public function verify(
        Bundle $bundle,
        ?TrustedRoot $trustedRoot,
        string $artifactPathOrDigest,
        ?string $publicKeyPath = null,
        ?string $expectedCertIdentity = null,
        ?string $expectedCertIssuer = null
    ): bool {
        // 1. Get artifact digest
        try {
            $artifactDigest = $this->getArtifactDigest($artifactPathOrDigest);
        } catch (\Exception $e) {
            throw new \RuntimeException("Failed to get artifact digest: " . $e->getMessage(), 0, $e);
        }

        $verificationMaterial = $bundle->getVerificationMaterial();
        if ($verificationMaterial === null) {
            throw new \RuntimeException("Bundle missing verification material");
        }

        if ($publicKeyPath) {
            // 2a. Verify using provided public key
            if (!file_exists($publicKeyPath)) {
                throw new \InvalidArgumentException("Public key file not found: {$publicKeyPath}");
            }
            $publicKeyPem = file_get_contents($publicKeyPath);
            return $this->verifyWithPublicKey($bundle, $publicKeyPem, $artifactDigest);
        } elseif ($expectedCertIdentity && $expectedCertIssuer) {
            // 2b. Verify using certificate chain and trusted root
            if (!$trustedRoot) {
                 throw new \InvalidArgumentException("Trusted root is required for certificate-based verification");
            }
            return $this->verifyWithCertificate($bundle, $trustedRoot, $artifactDigest, $expectedCertIdentity, $expectedCertIssuer);
        } else {
            // Should not happen due to checks in CLI
            throw new \InvalidArgumentException("Insufficient options for verification");
        }
    }

    private function verifyWithPublicKey(Bundle $bundle, string $publicKeyPem, string $artifactDigest): bool
    {
        try {
            /** @var \phpseclib3\Crypt\EC\PublicKey $publicKey */
            $publicKey = PublicKeyLoader::load($publicKeyPem);
        } catch (\Exception $e) {
            throw new \RuntimeException("Failed to load public key: " . $e->getMessage(), 0, $e);
        }

        if (!($publicKey instanceof EC)) {
             throw new \RuntimeException("Only EC keys are currently supported");
        }

        $signature = '';
        $hashAlgo = 'sha256';

        if ($bundle->hasMessageSignature()) {
            $msgSig = $bundle->getMessageSignature();
            $signature = $msgSig->getSignature();
            if (empty($signature)) throw new \RuntimeException("Bundle message signature is empty");

            $messageDigest = $msgSig->getMessageDigest();
            if (!$messageDigest || $messageDigest->getAlgorithm() !== HashAlgorithm::SHA2_256) {
                throw new \RuntimeException("Only SHA256 message digest is supported");
            }
            if ($messageDigest->getDigest() !== hex2bin($artifactDigest)) {
                 throw new \RuntimeException("Artifact digest does not match message digest in bundle");
            }
            $dataHashed = $messageDigest->getDigest(); // This is the raw digest

            if ($this->verifyPrecomputedHash($publicKey, $dataHashed, $signature)) {
                 return true;
            } else {
                 throw new \RuntimeException("Signature verification failed for MessageSignature with precomputed hash");
            }

        } elseif ($bundle->hasDsseEnvelope()) {
            $envelope = $bundle->getDsseEnvelope();
            if (count($envelope->getSignatures()) === 0) throw new \RuntimeException("DSSE envelope has no signatures");
            $signature = $envelope->getSignatures()[0]->getSig();
            if (empty($signature)) throw new \RuntimeException("DSSE signature is empty");

            $payloadType = $envelope->getPayloadType();
            $payload = $envelope->getPayload();
            $paeData = sprintf(
                "DSSEv1 %d %s %d %s",
                strlen($payloadType), $payloadType,
                strlen($payload), $payload
            );
            
            $publicKey = $publicKey->withHash($hashAlgo);

            if ($publicKey->verify($paeData, $signature)) {
                return true;
            } else {
                 throw new \RuntimeException("Signature verification failed for DSSE Envelope");
            }
        } else {
            throw new \RuntimeException("Bundle has no supported content");
        }
    }

    private function verifyWithCertificate(Bundle $bundle, TrustedRoot $trustedRoot, string $artifactDigest, string $expectedIdentity, string $expectedIssuer): bool
    {
        $verificationMaterial = $bundle->getVerificationMaterial();
        
        // 1. Extract Leaf Certificate
        $leafCertBytes = null;
        $intermediatesBytes = [];
        
        $certChainMessage = $verificationMaterial->getX509CertificateChain();
        if ($certChainMessage && count($certChainMessage->getCertificates()) > 0) {
            $certs = $certChainMessage->getCertificates();
            $leafCertBytes = $certs[0]->getRawBytes();
            for ($i = 1; $i < count($certs); $i++) {
                 $intermediatesBytes[] = $certs[$i]->getRawBytes();
            }
        } else {
            $certMessage = $verificationMaterial->getCertificate();
            if ($certMessage) {
                $leafCertBytes = $certMessage->getRawBytes();
            }
        }

        if ($leafCertBytes === null) {
            throw new \RuntimeException("Bundle does not contain an X.509 certificate or chain");
        }
        
        $x509 = new \phpseclib3\File\X509();
        
        // Load Trusted Roots
        foreach ($trustedRoot->getCertificateAuthorities() as $ca) {
            if ($ca->hasCertChain()) {
                foreach ($ca->getCertChain()->getCertificates() as $trustedCert) {
                     $x509->loadCA($trustedCert->getRawBytes());
                }
            }
        }
        
        // Load Intermediates as CAs so they can build the chain
        foreach ($intermediatesBytes as $intermediate) {
             $x509->loadCA($intermediate);
        }

        $cert = $x509->loadX509($leafCertBytes);
        if (!$cert) {
            throw new \RuntimeException("Failed to parse leaf certificate");
        }

        if (!$x509->validateSignature()) {
            throw new \RuntimeException("Failed to validate certificate chain against trusted roots");
        }

        // 2. Verify Certificate Identity and Issuer
        $issuerOid = '1.3.6.1.4.1.57264.1.1';
        $actualIssuer = $x509->getExtension($issuerOid);
        if ($actualIssuer !== $expectedIssuer) {
            throw new \RuntimeException("Certificate issuer mismatch. Expected: {$expectedIssuer}, Got: " . ($actualIssuer ?? 'none'));
        }

        $sans = $x509->getExtension('id-ce-subjectAltName');
        $identityMatched = false;
        if (is_array($sans)) {
            foreach ($sans as $san) {
                // Identity could be a URI or an Email
                if (isset($san['uniformResourceIdentifier']) && $san['uniformResourceIdentifier'] === $expectedIdentity) {
                    $identityMatched = true;
                    break;
                }
                if (isset($san['rfc822Name']) && $san['rfc822Name'] === $expectedIdentity) {
                    $identityMatched = true;
                    break;
                }
            }
        }
        
        if (!$identityMatched) {
             throw new \RuntimeException("Certificate identity mismatch. Expected: {$expectedIdentity}");
        }

        // 3. Verify SCT (Signed Certificate Timestamp) Presence
        $sctOid = '1.3.6.1.4.1.11129.2.4.2';
        $sctExt = $x509->getExtension($sctOid);
        if (!$sctExt) {
            throw new \RuntimeException("Certificate does not contain an SCT extension");
        }

        // 4. Extract Public Key and Verify Signature
        $publicKey = $x509->getPublicKey();
        if (!($publicKey instanceof EC)) {
            throw new \RuntimeException("Only EC keys are currently supported in certificates");
        }

        $signature = '';
        $hashAlgo = 'sha256';

        if ($bundle->hasMessageSignature()) {
            $msgSig = $bundle->getMessageSignature();
            $signature = $msgSig->getSignature();
            if (empty($signature)) throw new \RuntimeException("Bundle message signature is empty");

            $messageDigest = $msgSig->getMessageDigest();
            if (!$messageDigest || $messageDigest->getAlgorithm() !== HashAlgorithm::SHA2_256) {
                throw new \RuntimeException("Only SHA256 message digest is supported");
            }
            if ($messageDigest->getDigest() !== hex2bin($artifactDigest)) {
                 throw new \RuntimeException("Artifact digest does not match message digest in bundle");
            }
            $dataHashed = $messageDigest->getDigest(); // This is the raw digest

            if (!$this->verifyPrecomputedHash($publicKey, $dataHashed, $signature)) {
                 throw new \RuntimeException("Signature verification failed for MessageSignature with precomputed hash");
            }

        } elseif ($bundle->hasDsseEnvelope()) {
            $envelope = $bundle->getDsseEnvelope();
            if (count($envelope->getSignatures()) === 0) throw new \RuntimeException("DSSE envelope has no signatures");
            $signature = $envelope->getSignatures()[0]->getSig();
            if (empty($signature)) throw new \RuntimeException("DSSE signature is empty");

            $payloadType = $envelope->getPayloadType();
            $payload = $envelope->getPayload();
            $paeData = sprintf(
                "DSSEv1 %d %s %d %s",
                strlen($payloadType), $payloadType,
                strlen($payload), $payload
            );
            
            $publicKey = $publicKey->withHash($hashAlgo);

            if (!$publicKey->verify($paeData, $signature)) {
                 throw new \RuntimeException("Signature verification failed for DSSE Envelope");
            }
        } else {
            throw new \RuntimeException("Bundle has no supported content");
        }

        // 5. Verify Rekor Inclusion Proof
        $tlogEntries = $verificationMaterial->getTlogEntries();
        if (count($tlogEntries) === 0) {
             throw new \RuntimeException("Bundle does not contain transparency log entries");
        }
        $this->verifyRekorInclusionProof($tlogEntries[0], $trustedRoot);

        // For now, if everything matches, we throw a specific exception 
        // so we know we got this far in the tests.
        throw new \RuntimeException("Signature verified against leaf certificate. Certificate chain validation not implemented.");
    }

    private function verifyRekorInclusionProof(\Dev\Sigstore\Rekor\V1\TransparencyLogEntry $tlogEntry, TrustedRoot $trustedRoot): void
    {
        $inclusionProof = $tlogEntry->getInclusionProof();
        if (!$inclusionProof) {
            throw new \RuntimeException("Transparency log entry is missing an inclusion proof");
        }
        
        $checkpoint = $inclusionProof->getCheckpoint();
        if (!$checkpoint) {
            throw new \RuntimeException("Inclusion proof is missing a checkpoint");
        }
        
        $envelope = $checkpoint->getEnvelope();
        $parts = explode("\n\u{2014} ", $envelope);
        if (count($parts) !== 2) {
             throw new \RuntimeException("Invalid checkpoint format");
        }
        
        $signedBody = rtrim($parts[0], "\n") . "\n";
        $sigLine = trim($parts[1]);
        $sigParts = explode(" ", $sigLine);
        if (count($sigParts) !== 2) {
             throw new \RuntimeException("Invalid checkpoint signature line");
        }
        
        $origin = $sigParts[0];
        $keyIdAndSig = base64_decode($sigParts[1]);
        $keyId = substr($keyIdAndSig, 0, 4);
        $signature = substr($keyIdAndSig, 4);

        $bodyParts = explode("\n", trim($signedBody));
        $treeSize = (int)$bodyParts[1];
        $rootHash = base64_decode($bodyParts[2]);

        $keyFound = false;
        $sigValid = false;

        foreach ($trustedRoot->getTlogs() as $tlog) {
            $tlogKeyId = null;
            if ($tlog->hasCheckpointKeyId() && $tlog->getCheckpointKeyId()->getKeyId() !== '') {
                 $tlogKeyId = $tlog->getCheckpointKeyId()->getKeyId();
            } elseif ($tlog->hasLogId() && $tlog->getLogId()->getKeyId() !== '') {
                 $tlogKeyId = $tlog->getLogId()->getKeyId();
            }
            
            if ($tlogKeyId !== null && substr($tlogKeyId, 0, 4) === $keyId) {
                 $keyFound = true;
                 $pubKeyDer = $tlog->getPublicKey()->getRawBytes();
                 $pubKeyPem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($pubKeyDer), 64, "\n") . "-----END PUBLIC KEY-----\n";
                 $pk = \phpseclib3\Crypt\PublicKeyLoader::load($pubKeyPem);
                 
                 try {
                     if ($pk->verify($signedBody, $signature)) {
                          $sigValid = true;
                          break;
                     }
                 } catch (\Exception $e) {}
                 
                 try {
                     if ($pk->withHash('sha256')->verify($signedBody, $signature)) {
                          $sigValid = true;
                          break;
                     }
                 } catch (\Exception $e) {}
            }
        }
        
        if (!$keyFound) {
             throw new \RuntimeException("Could not find a matching public key for the checkpoint in the trusted root");
        }
        if (!$sigValid) {
             throw new \RuntimeException("Checkpoint signature verification failed");
        }
        
        // Merkle Tree Math
        $canonicalizedBody = $tlogEntry->getCanonicalizedBody();
        $leafHash = hash('sha256', "\x00" . $canonicalizedBody, true);
        
        $logIndex = $inclusionProof->getLogIndex();
        $hashes = [];
        foreach ($inclusionProof->getHashes() as $h) {
            $hashes[] = $h;
        }
        
        $inner = strlen(decbin($logIndex ^ ($treeSize - 1)));
        $border = substr_count(decbin($logIndex >> $inner), '1');
        
        if (count($hashes) !== ($inner + $border)) {
             throw new \RuntimeException("Inclusion proof hash count mismatch");
        }
        
        $innerHashes = array_slice($hashes, 0, $inner);
        $borderHashes = array_slice($hashes, $inner);
        
        $seed = $leafHash;
        for ($i = 0; $i < count($innerHashes); $i++) {
            $h = $innerHashes[$i];
            if (($logIndex >> $i) & 1 === 0) {
                 $seed = hash('sha256', "\x01" . $seed . $h, true);
            } else {
                 $seed = hash('sha256', "\x01" . $h . $seed, true);
            }
        }
        
        foreach ($borderHashes as $h) {
             $seed = hash('sha256', "\x01" . $h . $seed, true);
        }
        
        if ($seed !== $rootHash) {
             throw new \RuntimeException("Inclusion proof verification failed: calculated root hash does not match checkpoint");
        }
    }

    private function verifyPrecomputedHash(EC\PublicKey $key, string $hashBytes, string $signature): bool
    {
        $params = \phpseclib3\Crypt\EC\Formats\Signature\ASN1::load($signature);
        if ($params === false || count($params) != 2) {
            return false;
        }
        $r = $params['r'];
        $s = $params['s'];

        $refClass = new \ReflectionClass($key);
        $curveProp = $refClass->getProperty('curve');
        $curveProp->setAccessible(true);
        $curve = $curveProp->getValue($key);

        $qaProp = $refClass->getProperty('QA');
        $qaProp->setAccessible(true);
        $QA = $qaProp->getValue($key);

        $order = $curve->getOrder();
        $one = new \phpseclib3\Math\BigInteger(1);
        $n_1 = $order->subtract($one);

        if (!$r->between($one, $n_1) || !$s->between($one, $n_1)) {
            return false;
        }

        $e = new \phpseclib3\Math\BigInteger($hashBytes, 256);
        $z = $e; 

        $w = $s->modInverse($order);
        list(, $u1) = $z->multiply($w)->divide($order);
        list(, $u2) = $r->multiply($w)->divide($order);

        if ($u1 instanceof \phpseclib3\Math\PrimeField\Integer) {
            $u1 = new \phpseclib3\Math\BigInteger($u1->toBytes(), 256);
        }
        if ($u2 instanceof \phpseclib3\Math\PrimeField\Integer) {
            $u2 = new \phpseclib3\Math\BigInteger($u2->toBytes(), 256);
        }

        $u1 = $curve->convertInteger($u1);
        $u2 = $curve->convertInteger($u2);

        list($x1, $y1) = $curve->multiplyAddPoints(
            [$curve->getBasePoint(), $QA],
            [$u1, $u2]
        );

        if ($x1 instanceof \phpseclib3\Math\PrimeField\Integer) {
            $x1 = new \phpseclib3\Math\BigInteger($x1->toBytes(), 256);
        } else {
            $x1 = $curve->convertInteger($x1);
        }
        
        list(, $x1) = $x1->divide($order);

        return $x1->equals($r);
    }

    private function extractTimeFromTsaToken(string $der): ?\DateTime
    {
        try {
            $decoded = \phpseclib3\File\ASN1::decodeBER($der);
            return $this->findGeneralizedTimeInAsn1($decoded);
        } catch (\Exception $e) {
            return null;
        }
    }

    private function findGeneralizedTimeInAsn1($asnArray): ?\DateTime
    {
        if (!is_array($asnArray)) return null;

        foreach ($asnArray as $node) {
            if (isset($node['type']) && $node['type'] === 24 && isset($node['content'])) {
                if ($node['content'] instanceof \DateTime) {
                     return $node['content'];
                }
                if (is_string($node['content'])) {
                     try { return new \DateTime($node['content']); } catch (\Exception $e) {}
                }
            }
            
            if (isset($node['type']) && $node['type'] === 4 && isset($node['content']) && is_string($node['content'])) {
                try {
                    $innerDecoded = \phpseclib3\File\ASN1::decodeBER($node['content']);
                    $time = $this->findGeneralizedTimeInAsn1($innerDecoded);
                    if ($time) return $time;
                } catch (\Exception $e) {
                    // Ignore
                }
            }

            if (isset($node['content']) && is_array($node['content'])) {
                $res = $this->findGeneralizedTimeInAsn1($node['content']);
                if ($res) return $res;
            }
        }
        return null;
    }

    private function getArtifactDigest(string $artifactPathOrDigest): string
    {
        if (str_starts_with($artifactPathOrDigest, 'sha256:')) {
            $hash = substr($artifactPathOrDigest, strlen('sha256:'));
            if (preg_match('/^[a-f0-9]{64}$/', $hash)) {
                return $hash;
            }
            throw new \InvalidArgumentException("Invalid SHA256 digest format");
        }

        if (!file_exists($artifactPathOrDigest)) {
            throw new \InvalidArgumentException("Artifact file not found: {$artifactPathOrDigest}");
        }
        $hash = hash_file('sha256', $artifactPathOrDigest);
        if ($hash === false) {
            throw new \RuntimeException("Failed to hash artifact file");
        }
        return $hash;
    }
}
