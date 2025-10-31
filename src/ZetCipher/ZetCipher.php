<?php

/**
 * ZetCipher - Cryptography for secure token and verification
 * 
 * Nama     : anonputraid
 * Dibuat   : 07/08/2025
 *
 */

namespace ZetCipher;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Str;
use ZetCipher\Encryption\ConventionalEncrytion;
use ZetCipher\Encryption\PersonEncryption;
use ZetCipher\Encryption\HandshakeEncryption;

class ZetCipher
{
    public static function encode(string $data, ?int $expires = null, ?string $passphrase = null, ?int $coordinates = null, ?string $planet = null, ?int $passport = null)
    {
        return ConventionalEncrytion::encode($data, $expires, $passphrase, $coordinates, $planet, $passport);
    }

    public static function decode(string $token, ?string $passphrase = null, ?int $coordinates = null, ?string $planet = null, ?int $passport = null)
    {
        return ConventionalEncrytion::decode($token, $passphrase, $coordinates, $planet, $passport);
    }

    public static function generateLink(string $data, string $target, ?int $expires = null, ?string $passphrase = null, ?int $coordinates = null, ?string $planet = null, ?int $passport = null): string
    {
        $token = self::encode($data, $expires, $passphrase, $coordinates, $planet, $passport);

        if (function_exists('route') && !str_contains($target, '/')) {
            $url = route($target);
        } else {
            $url = url($target);
        }

        $delimiter = str_contains($url, '?') ? '&' : '?';
        return $url . $delimiter . 'token=' . $token;
    }

    public static function validateLink(?string $token = null): bool|string
    {
        if ($token === null && function_exists('request')) {
            $token = request()->query('token');
        }

        if (empty($token)) {
            throw new \InvalidArgumentException("[ZetCipher] Token tidak ditemukan di URL.");
        }

        return self::decode($token);
    }

    public static function sign(?string $data = null, ?int $expires = null, ?string $passphrase = null, ?int $coordinates = null, ?string $planet = null, ?int $passport = null)
    {
        return PersonEncryption::encode($data, $expires, $passphrase, $coordinates, $planet, $passport);
    }

    public static function verifySign(string $token, ?string $passphrase = null, ?int $coordinates = null, ?string $planet = null, ?int $passport = null)
    {
        return PersonEncryption::decode($token, $passphrase, $coordinates, $planet, $passport);
    }

    public static function handshake(string $id, ?string $data = null, ?int $expires = null, ?string $passphrase = null, ?int $coordinates = null, ?string $planet = null, ?int $passport = null)
    {
        return HandshakeEncryption::encode($id, $data, $expires, $passphrase, $coordinates, $planet, $passport);
    }

    public static function verifyHandshake(string $token, ?string $passphrase = null, ?int $coordinates = null, ?string $planet = null, ?int $passport = null)
    {
        return HandshakeEncryption::decode($token, $passphrase, $coordinates, $planet, $passport);
    }
}