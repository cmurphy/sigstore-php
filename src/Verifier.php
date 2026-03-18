<?php

namespace Sigstore;

use Dev\Sigstore\Bundle\V1\Bundle;
use Dev\Sigstore\Trustroot\V1\TrustedRoot;
use Google\Protobuf\Internal\Message;

class Verifier
{
    public function loadBundle(string $bundlePath): Bundle
    {
        if (!file_exists($bundlePath)) {
            throw new \InvalidArgumentException("Bundle file not found: {$bundlePath}");
        }

        $jsonContents = file_get_contents($bundlePath);
        if ($jsonContents === false) {
            throw new \RuntimeException("Could not read bundle file: {$bundlePath}");
        }

        $bundle = new Bundle();
        try {
            // Adjust to handle potential lowerCamelCase in JSON
            $this->fromJsonString($bundle, $jsonContents);
        } catch (\Exception $e) {
            throw new \RuntimeException("Failed to parse bundle JSON: " . $e->getMessage(), 0, $e);
        }

        return $bundle;
    }

    public function loadTrustedRoot(string $trustedRootPath): TrustedRoot
    {
        if (!file_exists($trustedRootPath)) {
            throw new \InvalidArgumentException("Trusted root file not found: {$trustedRootPath}");
        }

        $jsonContents = file_get_contents($trustedRootPath);
        if ($jsonContents === false) {
            throw new \RuntimeException("Could not read trusted root file: {$trustedRootPath}");
        }

        $trustedRoot = new TrustedRoot();
        try {
            $this->fromJsonString($trustedRoot, $jsonContents);
        } catch (\Exception $e) {
            throw new \RuntimeException("Failed to parse trusted root JSON: " . $e->getMessage(), 0, $e);
        }

        return $trustedRoot;
    }

    // Helper to deserialize JSON to Protobuf, handling lowerCamelCase keys
    private function fromJsonString(Message $message, string $jsonString): void
    {
        $data = json_decode($jsonString, true, 512, JSON_THROW_ON_ERROR);
        $message->mergeFromJsonString(json_encode($this->convertKeysToSnakeCase($data)));
    }

    private function convertKeysToSnakeCase(array $data): array
    {
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

    public function verify(/* ... */): bool
    {
        // TODO: Implement full verification logic
        return true;
    }
}
