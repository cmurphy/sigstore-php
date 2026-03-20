<?php

namespace Sigstore;

use phpseclib3\File\ASN1;
use phpseclib3\File\X509;
use phpseclib3\Crypt\PublicKeyLoader;

class SctVerifier
{
    /**
     * Verify the embedded Signed Certificate Timestamp (SCT) within a Fulcio leaf certificate.
     * 
     * @param string $leafCertDer The raw DER bytes of the Fulcio leaf certificate.
     * @param string $issuerCertDer The raw DER bytes of the issuer (intermediate) certificate.
     * @param \Dev\Sigstore\Trustroot\V1\TrustedRoot $trustedRoot The Sigstore TrustedRoot.
     * @throws \RuntimeException If the SCT cannot be verified.
     */
    public static function verify(string $leafCertDer, string $issuerCertDer, \Dev\Sigstore\Trustroot\V1\TrustedRoot $trustedRoot): void
    {
        $x509 = new X509();
        $cert = $x509->loadX509($leafCertDer);
        
        $sctOid = '1.3.6.1.4.1.11129.2.4.2';
        $sctExt = $x509->getExtension($sctOid);
        
        if (!$sctExt) {
            throw new \RuntimeException("Certificate does not contain an SCT extension");
        }

        $decodedSct = ASN1::decodeBER($sctExt);
        $sctBytesRaw = $decodedSct[0]['content'];

        $sctLen = unpack('n', substr($sctBytesRaw, 2, 2))[1];
        $sctBytes = substr($sctBytesRaw, 4, $sctLen);

        $version = ord($sctBytes[0]);
        if ($version !== 0) {
            throw new \RuntimeException("Unsupported SCT version: $version");
        }

        $logId = substr($sctBytes, 1, 32);
        $timestamp = unpack('J', substr($sctBytes, 33, 8))[1];
        $extLen = unpack('n', substr($sctBytes, 41, 2))[1];
        $extensions = substr($sctBytes, 43, $extLen);

        $sigOffset = 43 + $extLen;
        $hashAlg = ord($sctBytes[$sigOffset]);
        $sigAlg = ord($sctBytes[$sigOffset + 1]);
        if ($hashAlg !== 4) { // SHA256
            throw new \RuntimeException("Unsupported SCT hash algorithm (expected SHA256)");
        }

        $sigLen = unpack('n', substr($sctBytes, $sigOffset + 2, 2))[1];
        $signature = substr($sctBytes, $sigOffset + 4, $sigLen);

        // 2. Strip SCT from TBSCertificate
        $tbsPrecert = self::stripSctExtension($leafCertDer);

        // 3. Get Issuer Key ID
        $issuerX509 = new X509();
        $issuerX509->loadX509($issuerCertDer);
        $issuerPubKeyPem = $issuerX509->getPublicKey()->toString('PKCS8');
        $issuerSpkiDer = base64_decode(str_replace(['-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----', "\r", "\n"], '', $issuerPubKeyPem));
        $issuerKeyId = hash('sha256', $issuerSpkiDer, true);

        // 4. Pack digitally-signed struct
        $tbsLen = strlen($tbsPrecert);
        $len1 = ($tbsLen >> 16) & 0xFF;
        $len2 = ($tbsLen >> 8) & 0xFF;
        $len3 = $tbsLen & 0xFF;

        // precert_entry is 1
        $digitallySigned = pack("CCJn", 0, 0, $timestamp, 1) . $issuerKeyId . pack("CCC", $len1, $len2, $len3) . $tbsPrecert . pack("n", $extLen) . $extensions;

        // 5. Find CT Log Public Key
        $ctKeyPem = null;
        foreach ($trustedRoot->getCtlogs() as $ctlog) {
            $ctKeyDer = $ctlog->getPublicKey()->getRawBytes();
            $ctLogId = hash('sha256', $ctKeyDer, true);
            if ($ctLogId === $logId) {
                $ctKeyPem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($ctKeyDer), 64, "\n") . "-----END PUBLIC KEY-----\n";
                break;
            }
        }

        if (!$ctKeyPem) {
            throw new \RuntimeException("CT Log key not found for log ID: " . bin2hex($logId));
        }

        $pk = PublicKeyLoader::load($ctKeyPem);
        $isValid = $pk->withHash('sha256')->verify($digitallySigned, $signature);

        if (!$isValid) {
            error_log(sprintf("SCT Verification Failed! logId=%s, sigLen=%d, digitallySignedLen=%d", bin2hex($logId), strlen($signature), strlen($digitallySigned)));
            error_log("Leaf Cert MD5: " . md5($leafCertDer));
            error_log("Issuer Cert MD5: " . md5($issuerCertDer));
            throw new \RuntimeException("SCT signature verification failed");
        }
    }

    private static function getLengthLength(int $firstByte): int {
        if (($firstByte & 0x80) === 0) return 0;
        return $firstByte & 0x7F;
    }

    private static function getLength(string $der, int $offset, int &$lengthLength): int {
        $firstByte = ord($der[$offset]);
        if (($firstByte & 0x80) === 0) {
            $lengthLength = 1; return $firstByte;
        }
        $lengthLength = ($firstByte & 0x7F) + 1;
        $len = 0;
        for ($i = 1; $i < $lengthLength; $i++) {
            $len = ($len << 8) | ord($der[$offset + $i]);
        }
        return $len;
    }

    private static function skipElement(string $der, int $offset): int {
        $ll = 0;
        $len = self::getLength($der, $offset + 1, $ll);
        return $offset + 1 + $ll + $len;
    }

    private static function stripSctExtension(string $certBytes): string {
        $ll = 0; 
        self::getLength($certBytes, 1, $ll); 
        $tbsOffset = 1 + $ll;
        
        $tbsLl = 0; 
        $tbsLen = self::getLength($certBytes, $tbsOffset + 1, $tbsLl); 
        $tbsHeaderLen = 1 + $tbsLl;
        
        $tbsBytes = substr($certBytes, $tbsOffset, $tbsHeaderLen + $tbsLen);
        $oidHex = "060a2b06010401d679020402";
        $sctPos = strpos($tbsBytes, hex2bin($oidHex));
        
        if ($sctPos === false) {
            return $tbsBytes;
        }

        $seqStart = $sctPos - 2;
        if (ord($tbsBytes[$seqStart]) !== 0x30) {
            $seqStart = $sctPos - 3;
            if (ord($tbsBytes[$seqStart]) !== 0x30) $seqStart = $sctPos - 4;
        }
        
        $sctExtLl = 0; 
        $sctExtLen = self::getLength($tbsBytes, $seqStart + 1, $sctExtLl); 
        $extTotalLen = 1 + $sctExtLl + $sctExtLen;
        
        $newTbsBytes = substr($tbsBytes, 0, $seqStart) . substr($tbsBytes, $seqStart + $extTotalLen);
        
        // Robustly find A3 tag by skipping top-level TBSCertificate elements
        $offset = $tbsHeaderLen;
        $a3Pos = -1;
        while ($offset < strlen($newTbsBytes)) {
            if (ord($newTbsBytes[$offset]) === 0xA3) {
                $a3Pos = $offset;
                break;
            }
            $offset = self::skipElement($newTbsBytes, $offset);
        }
        
        if ($a3Pos === -1) {
             throw new \RuntimeException("Could not locate X509v3 Extensions block");
        }

        $a3Ll = 0; 
        $a3Len = self::getLength($newTbsBytes, $a3Pos + 1, $a3Ll);
        
        $seqPos = $a3Pos + 1 + $a3Ll;
        $seqLl = 0; 
        $seqLen = self::getLength($newTbsBytes, $seqPos + 1, $seqLl);
        
        $newSeqLen = $seqLen - $extTotalLen; 
        $newSeqLengthEncoded = ASN1::encodeLength($newSeqLen);
        $newA3Len = $a3Len - $extTotalLen - ($seqLl - strlen($newSeqLengthEncoded)); 
        $newA3LengthEncoded = ASN1::encodeLength($newA3Len);
        
        $beforeA3 = substr($newTbsBytes, 0, $a3Pos + 1);
        $afterA3Len = substr($newTbsBytes, $seqPos);
        $beforeSeq = substr($afterA3Len, 0, 1);
        $afterSeqLen = substr($afterA3Len, 1 + $seqLl);
        
        $fixedExts = $beforeA3 . $newA3LengthEncoded . $beforeSeq . $newSeqLengthEncoded . $afterSeqLen;
        $newTbsLen = $tbsLen - (strlen($tbsBytes) - strlen($fixedExts));
        $newTbsLengthEncoded = ASN1::encodeLength($newTbsLen);
        
        return "\x30" . $newTbsLengthEncoded . substr($fixedExts, $tbsHeaderLen);
    }
}
