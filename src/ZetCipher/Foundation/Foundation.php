<?php

namespace ZetCipher\Foundation;

use Illuminate\Database\Eloquent\Attributes\Boot;

/**
 * ZetCipher - Cryptography for secure token and verification
 * 
 * Nama     : anonputraid
 * Dibuat   : 07/08/2025
 *
 */

class Foundation
{
    public static function isZetCipherConfigured(?string $envPath = null): bool
    {
        if (is_null($envPath) && function_exists('base_path')) {
            $envPath = base_path('.env');
        } elseif (is_null($envPath)) {
            $envPath = __DIR__ . '/../.env';
        }

        if (!file_exists($envPath)) {
            return false;
        }

        $envContent = file_get_contents($envPath);

        $requiredPatterns = [
            '/^ZETCIPHER_CIPHER=/m',
            '/^ZETCIPHER_ACCESS_KEY_ID=/m',
            '/^ZETCIPHER_ACCESS_KEY=/m',
            '/^ZETCIPHER_TOKEN_LIFETIME=3600/m',
        ];

        foreach ($requiredPatterns as $pattern) {
            if (!preg_match($pattern, $envContent)) {
                return false;
            }
        }

        return true;
    }

    public static function universe(string $n_str, ?string $planetary = null, ?string $passport = null): ?array
    {

        $planet = env('ZETCIPHER_CIPHER')
            ?: throw new \Exception("ZETCIPHER_CIPHER is not set or empty!");

        $cipher = $planetary ?: $planet;

        $serverPassport = env('ZETCIPHER_SIGNING_SECRET') ?: throw new \Exception("ZETCIPHER_SIGNING_SECRET is not set or empty!");
        $sign = $thisId = $passport ?? $serverPassport;

        $keyEncryption  = self::loadResourceForCipher('EncryptionResources.php', $cipher);
        $HideEncryption = self::loadResourceForCipher('HideResources.php', $cipher);
        $keySecret      = self::loadResourceForCipher('SystemResources.php', $cipher);

        $encryptionSynch = self::cipher($keyEncryption, $n_str);
        $HideSynch       = self::cipher($HideEncryption, $sign);
        $keySynch        = self::cipher($keySecret, $n_str);

        [$encCompound, $encReversion]   = self::createConversionMaps($encryptionSynch);
        [$secCompound, $secReversion]   = self::createConversionMaps($keySynch);

        [$hideCompound, $hideReversion] = self::makeSignature($HideSynch);

        return [
            'encryption' => [$encCompound, $encReversion],
            "hide"       => [$hideCompound, $hideReversion],
            'secret'     => [$secCompound, $secReversion],
        ];
    }

    private static function cipher(string $words, string $n_str): ?string
    {
        if (!self::isZetCipherConfigured()) {
            throw new \Exception(
                'ZetCipher configuration is incomplete. ' .
                    'Please ensure ZETCIPHER_CIPHER, ZETCIPHER_ACCESS_KEY_ID, ZETCIPHER_ACCESS_KEY, ' .
                    'and ZETCIPHER_TOKEN_LIFETIME are set correctly in your .env file.'
            );
        }

        $charList = str_split($words);

        $len = count($charList);
        $totalPermutations = self::factorial($len);

        // Validasi apakah n berada dalam jangkauan yang valid (1 <= n <= total)
        if (self::compare($n_str, '1') < 0 || self::compare($n_str, $totalPermutations) > 0) {
            return null;
        }

        // Konversi ke indeks berbasis nol (n-1)
        $n_zero_based = function_exists('bcsub') ? bcsub($n_str, '1') : (string)($n_str - 1);

        $result = '';

        for ($i = $len; $i > 0; $i--) {
            $blockSize = self::factorial($i - 1);
            [$charIndex_str, $n_zero_based] = self::divideAndRemainder($n_zero_based, $blockSize);
            $charIndex = (int)$charIndex_str;

            // Ambil karakter, tambahkan ke hasil, dan hapus dari daftar
            if (isset($charList[$charIndex])) {
                $result .= $charList[$charIndex];
                array_splice($charList, $charIndex, 1);
            } else {
                return null; // Error case jika indeks tidak ditemukan
            }
        }

        return $result;
    }

    public static function preparation(array $encodeMap, string $text): string
    {
        $out = '';
        for ($i = 0; $i < strlen($text); $i++) {
            $idx1 = self::getCharIndex1($text[$i]);
            if ($idx1 !== null && isset($encodeMap[$idx1])) {
                $out .= $encodeMap[$idx1];
            }
        }
        return $out ?: '00';
    }

    public static function combine(string $a, string $b): string
    {
        $i = strlen($a) - 1;
        $j = strlen($b) - 1;
        $carry = 0;
        $out = '';
        while ($i >= 0 || $j >= 0 || $carry) {
            $da = $i >= 0 ? ord($a[$i--]) - 48 : 0;
            $db = $j >= 0 ? ord($b[$j--]) - 48 : 0;
            $sum = $da + $db + $carry;
            $out .= chr(($sum % 10) + 48);
            $carry = intdiv($sum, 10);
        }
        return strrev($out);
    }

    public static function separate(?string $a = null, ?string $b = null): ?string
    {
        if ($a === null || $b === null) {
            return null;
        }

        preg_match('/^0*/', $a, $leadingZeros);
        $leadingZeros = $leadingZeros[0] ?? '';

        $a = ltrim($a, '0');
        $b = ltrim($b, '0');

        if ($a === '') {
            $a = '0';
        }
        if ($b === '') {
            $b = '0';
        }

        if (strlen($a) < strlen($b) || (strlen($a) === strlen($b) && strcmp($a, $b) < 0)) {
            return null;
        }

        $i = strlen($a) - 1;
        $j = strlen($b) - 1;
        $borrow = 0;
        $result = '';

        while ($i >= 0) {
            $digitA = (int)$a[$i] - $borrow;
            $digitB = $j >= 0 ? (int)$b[$j] : 0;

            if ($digitA < $digitB) {
                $digitA += 10;
                $borrow = 1;
            } else {
                $borrow = 0;
            }

            $result .= $digitA - $digitB;

            $i--;
            $j--;
        }

        $result = strrev($result);

        $result = ltrim($result, '0');

        if ($result === '') {
            $result = '0';
        }

        return $leadingZeros . $result;
    }


    public static function restore(array $decodeMap, ?string $num = null): ?string
    {
        if (empty($num)) return null;

        if (strlen($num) % 2 !== 0) return null;

        $chars = [];
        for ($i = 0; $i < strlen($num); $i += 2) {
            $pair = substr($num, $i, 2);
            if (!isset($decodeMap[$pair])) return null;
            $chars[] = self::innate()[$decodeMap[$pair] - 1];
        }
        return implode('', $chars);
    }

    public static function createConversionMaps(string $scrambled): array
    {
        $encode = [];
        $decode = [];
        for ($i = 0; $i < strlen($scrambled); $i++) {
            $index1 = $i + 1;
            $pair = sprintf('%02d', ord($scrambled[$i]) % 100);
            $encode[$index1] = $pair;
            $decode[$pair] = $index1;
        }
        return [$encode, $decode];
    }

    public static function makeSignature(string $scrambled): array
    {
        $encode = [];
        $decode = [];

        for ($i = 0; $i < strlen($scrambled); $i++) {
            $pair = $scrambled[$i];
            $encode[$i] = $pair;
            $decode[$pair] = $i;
        }

        return [$encode, $decode];
    }

    public static function applySignature(?string $numberString = null, array $map): string|bool
    {
        if (empty($numberString)) {
            return false;
        }

        return strtr($numberString, $map);
    }

    public static function scanText(?string $input = null): bool
    {
        return (bool) preg_match('/^[a-zA-Z0-9 -]+$/', $input);
    }

    public static function scanToken(string $input): bool
    {
        return (bool) preg_match('/^[0-9]+$/', $input);
    }

    public static function innate()
    {
        $a = array_merge(range(65, 90), range(97, 122), [49, 50, 51, 52, 53, 54, 55, 56, 57, 48], [45, 32, 47]);
        return implode('', array_map('chr', $a));
    }

    public static function generate(?string $folder = null, string $fileName = 'PrivateResources.php', ?string $type = null)
    {
        $folder = $folder ?? dirname(__DIR__, 1) . '/Resources';
        if (!is_dir($folder)) {
            mkdir($folder, 0777, true);
        }

        $filePath = $folder . '/' . $fileName;

        if (file_exists($filePath)) {
            return false;
        }

        $security_codes = [
            "ZET/ACS",
            "ZET/DEF",
            "ZET/GHI",
            "ZET/JKL",
            "ZET/MNO",
            "ZET/PQR",
            "ZET/STU",
            "ZET/VWX",
            "ZET/YZZ",
            "ZET/YZA",
            "ZET/BCD",
            "ZET/EFG",
            "ZET/HIJ",
            "ZET/KLM",
            "ZET/NOP",
            "ZET/QRS",
            "ZET/TUV",
            "ZET/WXY",
            "ZET/ZAB",
            "ZET/CDE",
            "ZET/FGH",
            "ZET/IJK",
            "ZET/LMN",
            "ZET/OPQ",
            "ZET/RST",
            "ZET/UVW",
            "ZET/XYZ",
            "ZET/GHJ",
            "ZET/ZAA",
            "ZET/QRT",
            "ZET/STV",
            "ZET/WXZ",
            "ZET/YZB",
            "ZET/BDE",
            "ZET/FGI",
            "ZET/HJL",
            "ZET/KMO",
            "ZET/NPQ",
            "ZET/RSU",
            "ZET/TVW",
            "ZET/WYa",
            "ZET/YAB",
            "ZET/CDF",
            "ZET/EGH",
            "ZET/HIK",
            "ZET/JLM",
            "ZET/NPR",
            "ZET/QST",
            "ZET/UVX",
            "ZET/WYZ",
            "ZET/ZAC",
            "ZET/BCE",
            "ZET/DFG",
            "ZET/GIJ",
            "ZET/HKL",
            "ZET/JMN",
            "ZET/LNP",
            "ZET/PQS",
            "ZET/RTU",
            "ZET/SVW",
            "ZET/UXY",
            "ZET/ZAD",
            "ZET/BEF",
            "ZET/CGH",
            "ZET/DIJ",
            "ZET/EKL",
            "ZET/FMN",
            "ZET/GOP",
            "ZET/HQR",
            "ZET/IST",
            "ZET/JUV",
            "ZET/KWX",
            "ZET/LYZ",
            "ZET/MZA",
            "ZET/NBC",
            "ZET/ODE",
            "ZET/PFG",
            "ZET/QGH",
            "ZET/RHI",
            "ZET/SIJ",
            "ZET/TKL"
        ];

        switch ($type) {
            case 'system':
                $numbers = range(0, 255);
                break;
            case 'private':
                $numbers = [
                    65,
                    66,
                    67,
                    68,
                    69,
                    70,
                    71,
                    72,
                    73,
                    74,
                    75,
                    76,
                    77,
                    78,
                    79,
                    80,
                    81,
                    82,
                    83,
                    84,
                    85,
                    86,
                    87,
                    88,
                    89,
                    90,
                    97,
                    98,
                    99,
                    100,
                    101,
                    102,
                    103,
                    104,
                    105,
                    106,
                    107,
                    108,
                    109,
                    110,
                    111,
                    112,
                    113,
                    114,
                    115,
                    116,
                    117,
                    118,
                    119,
                    120,
                    121,
                    122,
                    49,
                    50,
                    51,
                    52,
                    53,
                    54,
                    55,
                    56,
                    57,
                    48,
                    45,
                    32,
                    47
                ];
                break;
            default:
                $numbers = [49, 50, 51, 52, 53, 54, 55, 56, 57, 48];
                break;
        }

        $jumlah_baris = 81;
        $panjang_daftar_kode = count($security_codes);
        $output = [];

        for ($i = 0; $i < $jumlah_baris; $i++) {
            $key = $security_codes[$i % $panjang_daftar_kode];

            if (is_null($type)) {
                $shuffled = self::shuffleAndFilter($numbers);
            } else {
                $shuffled = $numbers;
                shuffle($shuffled);
            }

            $shuffled_str = implode('.', $shuffled);

            if (isset($output[$key])) {
                $suffix = 2;
                $newKey = $key . "#" . $suffix;
                while (isset($output[$newKey])) {
                    $suffix++;
                    $newKey = $key . "#" . $suffix;
                }
                $output[$newKey] = $shuffled_str;
            } else {
                $output[$key] = $shuffled_str;
            }
        }

        $content = "<?php\nreturn [\n";
        foreach ($output as $k => $v) {
            $content .= " '" . $k . "' => '" . $v . "',\n";
        }
        $content .= "];\n";

        file_put_contents($filePath, $content);
    }

    public static function translated($key)
    {
        $parts = explode('/', $key, 3);
        [$identity, $numeric, $padlock] = $parts;

        return $identity . "/" . $numeric . "/" . base64_decode($padlock);
    }

    private static function loadResourceForCipher(string $filename, string $cipher): string
    {
        $path = dirname(__DIR__, 1) . "/Resources/{$filename}";
        $resources = require $path;

        if (!isset($resources[$cipher]) || !is_string($resources[$cipher])) {
            throw new \UnexpectedValueException("Resource '{$cipher}' missing or invalid in {$filename}");
        }

        return self::read($resources[$cipher]);
    }

    private static function shuffleAndFilter(array $numbers): array
    {
        $shuffled = $numbers;

        do {
            shuffle($shuffled);
        } while ($shuffled[0] == 48);

        return $shuffled;
    }

    private static function factorial(int $num): string
    {
        $result = '1';
        for ($i = 2; $i <= $num; $i++) {
            $result = self::multiply($result, (string)$i);
        }
        return $result;
    }

    private static function compare(string $a, string $b): int
    {
        if (strlen($a) > strlen($b)) return 1;
        if (strlen($a) < strlen($b)) return -1;
        return strcmp($a, $b);
    }

    private static function multiply(string $num1, string $num2): string
    {
        if ($num1 == '0' || $num2 == '0') return '0';
        $len1 = strlen($num1);
        $len2 = strlen($num2);
        $result = array_fill(0, $len1 + $len2, 0);

        for ($i = $len1 - 1; $i >= 0; $i--) {
            $carry = 0;
            for ($j = $len2 - 1; $j >= 0; $j--) {
                $product = (int)$num1[$i] * (int)$num2[$j] + $result[$i + $j + 1] + $carry;
                $carry = floor($product / 10);
                $result[$i + $j + 1] = $product % 10;
            }
            $result[$i] += $carry;
        }

        return ltrim(implode('', $result), '0');
    }

    private static function divideAndRemainder(string $dividend, string $divisor): array
    {
        if ($divisor == '0' || self::compare($dividend, $divisor) < 0) {
            return ['0', $dividend];
        }
        $quotient = '';
        $current = '';
        for ($i = 0; $i < strlen($dividend); $i++) {
            $current .= $dividend[$i];
            $qDigit = 0;
            while (self::compare($current, $divisor) >= 0) {
                $current = function_exists('bcsub') ? bcsub($current, $divisor) : (string)($current - $divisor);
                $qDigit++;
            }
            $quotient .= $qDigit;
        }
        return [ltrim($quotient, '0') ?: '0', $current ?: '0'];
    }

    private static function getCharIndex1(string $ch): ?int
    {
        $pos = strpos(self::innate(), $ch);
        return $pos === false ? null : $pos + 1;
    }

    private static function read(string $s): string
    {
        $a = explode('.', $s);
        return implode('', array_map('chr', $a));
    }
}
