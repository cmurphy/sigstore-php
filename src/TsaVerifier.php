<?php

namespace Sigstore;

use Dev\Sigstore\Trustroot\V1\TrustedRoot;

class TsaVerifier
{
    public static function verify(string $tsaTokenDer, string $artifactSignature, TrustedRoot $trustedRoot, \DateTime $signingTime): bool
    {
        // Create temporary files for the openssl ts command
        $tokenFile = tempnam(sys_get_temp_dir(), 'tsa_token_');
        $sigFile = tempnam(sys_get_temp_dir(), 'tsa_sig_');
        $caFile = tempnam(sys_get_temp_dir(), 'tsa_ca_');
        $untrustedFile = tempnam(sys_get_temp_dir(), 'tsa_untrusted_');

        if (!$tokenFile || !$sigFile || !$caFile || !$untrustedFile) {
            throw new \RuntimeException("Failed to create temporary files for TSA verification");
        }

        try {
            file_put_contents($tokenFile, $tsaTokenDer);
            file_put_contents($sigFile, $artifactSignature);

            foreach ($trustedRoot->getTimestampAuthorities() as $ta) {
                if (!$ta->hasCertChain()) continue;

                $certs = $ta->getCertChain()->getCertificates();
                if (count($certs) === 0) continue;

                // The first certificate is the leaf (untrusted)
                $leafDer = $certs[0]->getRawBytes();
                $leafPem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($leafDer), 64, "\n") . "-----END CERTIFICATE-----\n";
                file_put_contents($untrustedFile, $leafPem);

                $caPem = "";
                for ($i = 1; $i < count($certs); $i++) {
                    $der = $certs[$i]->getRawBytes();
                    $caPem .= "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
                }
                
                // If there's only one cert (e.g. self-signed staging), use it as both
                if ($caPem === "") {
                     $caPem = $leafPem;
                }
                
                file_put_contents($caFile, $caPem);

                $command = sprintf(
                    "openssl ts -verify -in %s -data %s -CAfile %s -untrusted %s -attime %d 2>&1",
                    escapeshellarg($tokenFile),
                    escapeshellarg($sigFile),
                    escapeshellarg($caFile),
                    escapeshellarg($untrustedFile),
                    $signingTime->getTimestamp()
                );

                exec($command, $output, $returnCode);
                $outputStr = implode("\n", $output);
                $output = []; // clear for next iteration

                if ($returnCode === 0 && strpos($outputStr, 'Verification: OK') !== false) {
                    // Check validity window if specified
                    if ($ta->hasValidFor()) {
                        $validity = $ta->getValidFor();
                        $ts = $signingTime->getTimestamp();
                        
                        if ($validity->hasStart() && $ts < $validity->getStart()->getSeconds()) {
                             throw new \RuntimeException("TSA certificate is not yet valid at signing time");
                        }
                        if ($validity->hasEnd() && $ts > $validity->getEnd()->getSeconds()) {
                             throw new \RuntimeException("TSA certificate has expired at signing time");
                        }
                    }
                    return true;
                }
            }

            throw new \RuntimeException("TSA Verification failed against all trusted authorities");
        } finally {
            // Clean up temporary files
            @unlink($tokenFile);
            @unlink($sigFile);
            @unlink($caFile);
            @unlink($untrustedFile);
        }
    }
}
