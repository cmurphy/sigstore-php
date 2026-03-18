<?php

namespace Sigstore;

use Dev\Sigstore\Bundle\V1\Bundle;
use Dev\Sigstore\Trustroot\V1\TrustedRoot;
use Google\Protobuf\Internal\Message;
use Io\Intoto\Envelope;
use Io\Intoto\Signature;

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

    public function verify(Bundle $bundle, ?TrustedRoot $trustedRoot, string $artifactPathOrDigest): bool
    {
        // TODO: Implement full verification logic
        return true;
    }
}
