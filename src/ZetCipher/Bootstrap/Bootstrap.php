<?php

namespace ZetCipher\Bootstrap;

/**
 * Class Bootstrap
 */
class Bootstrap
{
    private static $obfuscatedPaths = [
        '8acde32d4768ae159bb6b45474bfcd3b' => '46.46.47.72.101.108.112.101.114.47.72.101.108.112.101.114.115.46.112.104.112',
    ];

    public static function boot(): void
    {
        foreach (self::$obfuscatedPaths as $path) {
            $decodedRelativePath = self::decodePath($path);

            $absolutePath = __DIR__ . $decodedRelativePath;

            if (file_exists($absolutePath)) {
                require_once $absolutePath;
            }
        }
    }

    private static function decodePath(string $asciiString): string
    {
        $asciiValues = explode('.', $asciiString);
        return implode('', array_map('chr', $asciiValues));
    }
}