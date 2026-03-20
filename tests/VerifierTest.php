<?php

namespace Sigstore\Tests;

use PHPUnit\Framework\TestCase;
use Sigstore\Verifier;
use Dev\Sigstore\Bundle\V1\Bundle;
use Dev\Sigstore\Trustroot\V1\TrustedRoot;
use Dev\Sigstore\Rekor\V1\TransparencyLogEntry;
use Dev\Sigstore\Rekor\V1\InclusionProof;
use Dev\Sigstore\Rekor\V1\Checkpoint;
use Dev\Sigstore\Trustroot\V1\TransparencyLogInstance;
use Dev\Sigstore\Common\V1\PublicKey;
use Dev\Sigstore\Common\V1\LogId;
use phpseclib3\Crypt\EC;

class VerifierTest extends TestCase
{
    private Verifier $verifier;

    protected function setUp(): void
    {
        $this->verifier = new Verifier();
    }

    public function testLoadBundleFailsWithInvalidMediaType()
    {
        $bundlePath = tempnam(sys_get_temp_dir(), 'bundle_');
        // Invalid media type missing 'version='
        file_put_contents($bundlePath, json_encode(['mediaType' => 'application/vnd.dev.sigstore.bundle+json']));
        
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Unsupported bundle media type');
        
        try {
            $this->verifier->loadBundle($bundlePath);
        } finally {
            @unlink($bundlePath);
        }
    }

    public function testLoadBundleFailsWithUnsupportedVersion()
    {
        $bundlePath = tempnam(sys_get_temp_dir(), 'bundle_');
        // Version 0.4 is currently unsupported based on the code
        file_put_contents($bundlePath, json_encode(['mediaType' => 'application/vnd.dev.sigstore.bundle+json;version=0.4']));
        
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Unsupported bundle media type: application/vnd.dev.sigstore.bundle+json;version=0.4');
        
        try {
            $this->verifier->loadBundle($bundlePath);
        } finally {
            @unlink($bundlePath);
        }
    }

    public function testVerifyRekorInclusionProofMerkleMath()
    {
        // This test sets up a mock inclusion proof and tests the core Merkle tree math
        // logic located inside the private verifyRekorInclusionProof method.
        
        // 1. Create a dummy EC key pair to sign the checkpoint
        $privateKey = EC::createKey('prime256v1');
        $publicKey = $privateKey->getPublicKey();
        $pubKeyDer = $publicKey->toString('PKCS8');
        // Extract raw DER (strip PEM headers)
        $pubKeyDer = base64_decode(str_replace(["-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----", "\n", "\r"], "", $pubKeyDer));
        $keyIdBytes = hash('sha256', $pubKeyDer, true);
        $keyIdHint = substr($keyIdBytes, 0, 4);

        // 2. Setup standard Merkle tree values
        $leafString = '{"spec":{"dsseV002":{"signatures":[{"content":"YmFzZTY0c2lnbmF0dXJl"}]}}}'; // "base64signature" base64 encoded
        $bundleSignature = 'base64signature';
        
        $leafHash = hash('sha256', "\x00" . $leafString, true);
        $logIndex = 3;
        $treeSize = 5;
        
        // Let's invent a simple tree.
        // Leaves: L0, L1, L2, L3, L4
        // We are proving L3 (logIndex = 3)
        // Tree structure for size 5:
        //       Root
        //      /    \
        //    N0..3   L4
        //    /   \
        // N0..1 N2..3
        // / \   / \
        // L0 L1 L2 L3
        
        // Dummy hashes for siblings
        $L2 = str_repeat("\x02", 32); // Sibling of L3
        $N0_1 = str_repeat("\x01", 32); // Sibling of N2..3
        $L4 = str_repeat("\x04", 32); // Sibling of N0..3
        
        // Calculate expected root
        $N2_3 = hash('sha256', "\x01" . $L2 . $leafHash, true); // L2 is left, L3 is right
        $N0_3 = hash('sha256', "\x01" . $N0_1 . $N2_3, true); // N0_1 is left, N2_3 is right
        $expectedRootHash = hash('sha256', "\x01" . $N0_3 . $L4, true); // N0_3 is left, L4 is right
        
        // The hashes array in the inclusion proof needs to be ordered correctly:
        // inner hashes (from leaf up to common ancestor of treeSize-1)
        // border hashes (from common ancestor up to root)
        
        // For logIndex=3, treeSize=5:
        // xor = 3 ^ 4 = 7 (111 in binary). inner = 3. 
        // Wait, logIndex 3 = 011, treeSize-1 = 4 = 100. XOR = 111.
        // Inner hashes count = 3? 
        // Let's trace the Verifier's logic to match exactly.
        $xor = $logIndex ^ ($treeSize - 1); // 3 ^ 4 = 7
        $inner = strlen(decbin($xor)); // strlen("111") = 3
        $border = substr_count(decbin($logIndex >> $inner), '1'); // 3 >> 3 = 0, count '1' is 0
        
        // Inner hashes need to be 3.
        // The path from L3 up to root of size 5:
        // Level 0: sibling is L2
        // Level 1: sibling is N0_1
        // Level 2: sibling is L4
        $hashes = [$L2, $N0_1, $L4];
        
        // 3. Construct the Checkpoint
        $signedBody = "Testing\n{$treeSize}\n" . base64_encode($expectedRootHash) . "\n";
        $checkpointSig = $privateKey->sign($signedBody);
        $envelope = $signedBody . "\n\u{2014} mock-origin " . base64_encode($keyIdHint . $checkpointSig) . "\n";

        // 4. Construct Protobuf Objects
        $checkpointObj = new Checkpoint();
        $checkpointObj->setEnvelope($envelope);

        $inclusionProof = new InclusionProof();
        $inclusionProof->setLogIndex($logIndex);
        $inclusionProof->setTreeSize($treeSize);
        $inclusionProof->setRootHash($expectedRootHash);
        $inclusionProof->setHashes($hashes);
        $inclusionProof->setCheckpoint($checkpointObj);

        $tlogEntry = new TransparencyLogEntry();
        $tlogEntry->setCanonicalizedBody($leafString);
        $tlogEntry->setInclusionProof($inclusionProof);

        $pubKeyObj = new PublicKey();
        $pubKeyObj->setRawBytes($pubKeyDer);
        
        $logIdObj = new LogId();
        $logIdObj->setKeyId($keyIdBytes);
        
        $tlogInstance = new TransparencyLogInstance();
        $tlogInstance->setPublicKey($pubKeyObj);
        $tlogInstance->setLogId($logIdObj);

        $trustedRoot = new TrustedRoot();
        $trustedRoot->setTlogs([$tlogInstance]);

        // 5. Invoke private method via Reflection
        $method = new \ReflectionMethod(Verifier::class, 'verifyRekorInclusionProof');
        $method->setAccessible(true);
        
        // If this doesn't throw an exception, the math is correct!
        $method->invoke($this->verifier, $tlogEntry, $trustedRoot, $bundleSignature);
        
        $this->assertTrue(true, 'Rekor Inclusion Proof Merkle math verified successfully.');
    }
}
