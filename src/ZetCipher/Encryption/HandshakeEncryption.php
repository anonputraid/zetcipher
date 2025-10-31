<?php

namespace ZetCipher\Encryption;

use ZetCipher\Foundation\Foundation;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Str;

class HandshakeEncryption
{
    public static function encode(string $id, ?string $data = null, ?int $expires = null, ?string $passphrase = null, ?int $coordinates = null, ?string $planet = null, ?int $passport = null): string
    {
        if (!Foundation::isZetCipherConfigured()) {
            throw new \Exception(
                'ZetCipher configuration incomplete. Ensure all ZETCIPHER environment variables are set.'
            );
        }

        if (!empty($data)) {
            if (!Foundation::scanText($data)) {
                throw new \InvalidArgumentException("Invalid input: only letters (a-z, A-Z) and numbers (0-9) are allowed.");
            }
        }

        $user = DB::table('users')->where('id', $id)->first();

        if (!$user) {
            throw new \InvalidArgumentException('[Zetcipher] User not found');
        }

        $zetcipherId = env('ZETCIPHER_ACCESS_KEY_ID')
            ?: throw new \Exception("ZETCIPHER_ACCESS_KEY_ID is not set or empty!");

        $pureKey = env('ZETCIPHER_ACCESS_KEY')
            ?: throw new \InvalidArgumentException("ZETCIPHER_ACCESS_KEY not found. Run 'php artisan zetcipher:key'.");

        $resources = Foundation::universe($coordinates ?? $zetcipherId, $planet ?? null, $passport ?? null);

        $key = Foundation::translated($pureKey);
        $expiresAt = $expires ?? time() + (int) env('ZETCIPHER_TOKEN_LIFETIME', 900);
        $payload =  $data . "/{$expiresAt}/{$user->id}/" ?? "" . "/{$expiresAt}/{$user->id}/";

        $extra = max(0, strlen($key) - strlen($payload) - 1);

        if ($extra > 0) {
            $payload .= getZetCipherSentences($extra);
        }

        $preparedPayload = Foundation::applySignature(
            Foundation::preparation($resources['encryption'][0], $payload),
            $resources["hide"][0]
        );

        $preparedKey = Foundation::applySignature(
            Foundation::preparation($resources['secret'][0], $key),
            $resources["hide"][0]
        );

        $combined = strlen($preparedPayload) < strlen($preparedKey)
            ? Foundation::combine($preparedKey, $preparedPayload)
            : Foundation::combine($preparedPayload, $preparedKey);


        if (!empty($passphrase)) {
            $preparedPassphrase = Foundation::applySignature(
                Foundation::preparation($resources['secret'][0], $passphrase),
                $resources["hide"][0]
            );

            $combined = strlen($combined) < strlen($preparedPassphrase)
                ? Foundation::combine($preparedPassphrase, $combined)
                : Foundation::combine($combined, $preparedPassphrase);
        }

        $identic = Foundation::applySignature(
            Foundation::preparation($resources['secret'][0], $user->id),
            $resources["hide"][0]
        );

        $combined = strlen($combined) < strlen($identic)
            ? Foundation::combine($identic, $combined)
            : Foundation::combine($combined, $identic);

        return Foundation::applySignature($combined, $resources["hide"][0]);
    }

    /**
     * Decode a ZetCipher token.
     *
     * @param string $token
     * @return string|false Decoded data on success, false on failure/invalid/expired
     * @throws \RuntimeException If configuration or required env values are missing
     */
    public static function decode(string $token, ?string $passphrase = null, ?int $coordinates = null, ?string $planet = null, ?string $passport = null)
    {
        if ($token === '') {
            return false;
        }

        if (!Foundation::isZetCipherConfigured()) {
            throw new \RuntimeException(
                'ZetCipher configuration incomplete. Ensure ZETCIPHER_CIPHER, ZETCIPHER_ACCESS_KEY_ID, ' .
                    'ZETCIPHER_ACCESS_KEY and ZETCIPHER_TOKEN_LIFETIME are set.'
            );
        }

        if (!Foundation::scanToken($token)) {
            return false;
        }

        $uuid = Auth::user()->id;

        $user = DB::table('users')->where('id', $uuid)->first();

        if (!$user) {
            throw new \InvalidArgumentException('[Zetcipher] User not found');
        }

        $zetcipherId = env('ZETCIPHER_ACCESS_KEY_ID') ?: throw new \RuntimeException('ZETCIPHER_ACCESS_KEY_ID is not set or empty!');
        $resources = Foundation::universe($coordinates ?? $zetcipherId, $planet ?? null, $passport ?? null);

        $rawKey = env('ZETCIPHER_ACCESS_KEY') ?: throw new \RuntimeException('ZETCIPHER_ACCESS_KEY is not set or empty!');
        $key    = Foundation::translated($rawKey);

        $token = Foundation::applySignature($token, $resources["hide"][1]);

        $keyNum = Foundation::applySignature(
            Foundation::preparation($resources['secret'][0], $key),
            $resources["hide"][0]
        );

        $identic = Foundation::applySignature(
            Foundation::preparation($resources['secret'][0], $user->id),
            $resources["hide"][0]
        );

        if (!empty($passphrase)) {
            $derivedSecret = Foundation::applySignature(
                Foundation::preparation($resources['secret'][0], $passphrase),
                $resources["hide"][0]
            );

            $unlockedToken =  Foundation::separate($token, $derivedSecret);

            $cleanToken    = Foundation::separate($unlockedToken, $keyNum);

            $cleanToken = Foundation::applySignature(
                Foundation::separate($cleanToken, $identic),
                $resources["hide"][1]
            );
        } else {
            $cleanToken = Foundation::separate($token, $keyNum);

            $cleanToken = Foundation::applySignature(
                Foundation::separate($cleanToken, $identic),
                $resources["hide"][1]
            );
        }

        $decoded    = Foundation::restore($resources['encryption'][1], $cleanToken);

        if (empty($decoded)) {
            return false;
        }

        [$data, $tsExpStr, $sign] = array_pad(explode('/', $decoded, 3), 2, '');

        if ($data === '' || !ctype_digit($tsExpStr) || (int) $tsExpStr < time() || str_replace('/', '', $sign) !== $user->id) {
            return false;
        }

        return $data == "zetcipher" ? true : $data;
    }
}