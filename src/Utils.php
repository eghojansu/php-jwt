<?php

declare(strict_types=1);

namespace Ekok\JWT;

class Utils
{
    const ALG_HS256 = 'HS256';
    const ALG_HS384 = 'HS384';
    const ALG_HS512 = 'HS512';
    const ALG_ES384 = 'ES384';
    const ALG_ES256 = 'ES256';
    const ALG_RS256 = 'RS256';
    const ALG_RS384 = 'RS384';
    const ALG_RS512 = 'RS512';
    const ALG_EDDSA = 'EdDSA';

    private const SUPPORTED_ALGORITHMS = array(
        self::ALG_HS256 => array('hash_hmac', 'SHA256'),
        self::ALG_HS384 => array('hash_hmac', 'SHA384'),
        self::ALG_HS512 => array('hash_hmac', 'SHA512'),
        self::ALG_ES384 => array('openssl', 'SHA384'),
        self::ALG_ES256 => array('openssl', 'SHA256'),
        self::ALG_RS256 => array('openssl', 'SHA256'),
        self::ALG_RS384 => array('openssl', 'SHA384'),
        self::ALG_RS512 => array('openssl', 'SHA512'),
        self::ALG_EDDSA => array('sodium_crypto', 'EdDSA'),
    );
    private const ASN1_INTEGER = 0x02;
    private const ASN1_SEQUENCE = 0x10;
    private const ASN1_BIT_STRING = 0x03;

    public static function sign(string $jwt, string $alg, $key): string
    {
        list($fun, $algorithm) = self::SUPPORTED_ALGORITHMS[$alg] ?? array(null, null);

        $signature = match($fun) {
            'hash_hmac' => self::signHashHmac($jwt, $algorithm, $key),
            'openssl' => self::signOpenSSL($jwt, $algorithm, $key),
            'sodium_crypto' => self::signSodiumCrypto($jwt, $key),
            default => null,
        };

        if (!$signature) {
            throw new \DomainException('Algorithm not supported');
        }

        return self::base64Encode(
            match($algorithm) {
                'ES256' => self::signatureFromDER($signature, 256),
                'ES384' => self::signatureFromDER($signature, 384),
                default => $signature,
            },
        );
    }

    public static function verify(
        string $seed,
        string $alg,
        string $rawSignature,
        $key,
    ): void {
        list($fun, $algorithm) = self::SUPPORTED_ALGORITHMS[$alg] ?? array(null, null);

        $decoded = self::base64Decode($rawSignature);
        $signature = match($alg) {
            'ES256', 'ES384' => self::signatureToDER($decoded),
            default => $decoded,
        };
        $verified = match($fun) {
            'hash_hmac' => self::verifyHashHmac($seed, $algorithm, $signature, $key),
            'openssl' => self::verifyOpenSSL($seed, $algorithm, $signature, $key),
            'sodium_crypto' => self::verifySodiumCrypto($seed, $signature, $key),
            default => null,
        };

        if (null === $verified) {
            throw new \DomainException('Algorithm not supported');
        }

        if (!$verified) {
            throw new \RuntimeException('Signature verification failed');
        }
    }

    public static function jsonEncode(array $data): string
    {
        return self::base64Encode(json_encode($data, JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR));
    }

    public static function jsonDecode(string $input): array
    {
        return json_decode(self::base64Decode($input), true, 512, JSON_BIGINT_AS_STRING|JSON_THROW_ON_ERROR);
    }

    private static function base64Encode(string $text): string
    {
        return str_replace('=', '', strtr(base64_encode($text), '+/', '-_'));
    }

    private static function base64Decode(string $text): string
    {
        return base64_decode(strtr($text . str_repeat('=', 4 - min(4, strlen($text) % 4)), '-_', '+/'));
    }

    private static function signHashHmac(string $data, string $algorithm, $key): string
    {
        if (!is_string($key)) {
            throw new \InvalidArgumentException('Key must be a string when using hmac');
        }

        return hash_hmac($algorithm, $data, $key, true);
    }

    private static function verifyHashHmac(string $data, string $algorithm, string $signature, $key): bool
    {
        return hash_equals(self::signHashHmac($data, $algorithm, $key), $signature);
    }

    private static function signOpenSSL(string $data, string $algorithm, $key): string
    {
        $signature = '';
        $success = openssl_sign($data, $signature, $key, $algorithm);

        if (!$success) {
            throw new \DomainException('OpenSSL unable to sign data');
        }

        return $signature;
    }

    private static function verifyOpenSSL(string $data, string $algorithm, string $signature, $key): bool
    {
        $result = openssl_verify($data, $signature, $key, $algorithm);

        if (0 > $result) {
            throw new \DomainException(sprintf('OpenSSL error: %s', openssl_error_string()));
        }

        return 0 < $result;
    }

    private static function signSodiumCrypto(string $data, $key): string
    {
        if (!is_string($key)) {
            throw new \InvalidArgumentException('Key must be a string when using EdDSA');
        }

        // The last non-empty line is used as the key.
        $lines = array_filter(explode("\n", $key));
        $key = base64_decode((string) end($lines));

        return sodium_crypto_sign_detached($data, $key);
    }

    private static function verifySodiumCrypto(string $data, string $signature, $key): bool
    {
        if (!is_string($key)) {
            throw new \InvalidArgumentException('Key must be a string when using EdDSA');
        }

        // The last non-empty line is used as the key.
        $lines = array_filter(explode("\n", $key));
        $key = base64_decode((string) end($lines));

        return sodium_crypto_sign_verify_detached($signature, $data, $key);
    }

    /**
     * Convert an ECDSA signature to an ASN.1 DER sequence
     *
     * @param   string $sig The ECDSA signature to convert
     * @return  string The encoded DER object
     */
    private static function signatureToDER(string $sig): string
    {
        // Separate the signature into r-value and s-value
        $length = max(1, (int) (strlen($sig) / 2));
        list($r, $s) = str_split($sig, $length > 0 ? $length : 1);

        // Trim leading zeros
        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        // Convert r-value and s-value from unsigned big-endian integers to
        // signed two's complement
        if (ord($r[0]) > 0x7f) {
            $r = "\x00" . $r;
        }

        if (ord($s[0]) > 0x7f) {
            $s = "\x00" . $s;
        }

        return self::encodeDER(
            self::ASN1_SEQUENCE,
            self::encodeDER(self::ASN1_INTEGER, $r) .
            self::encodeDER(self::ASN1_INTEGER, $s)
        );
    }

    /**
     * Encodes signature from a DER object.
     *
     * @param   string  $der binary signature in DER format
     * @param   int     $keySize the number of bits in the key
     *
     * @return  string  the signature
     */
    private static function signatureFromDER(string $der, int $keySize): string
    {
        // OpenSSL returns the ECDSA signatures as a binary ASN.1 DER SEQUENCE
        list($offset, $_) = self::readDER($der);
        list($offset, $r) = self::readDER($der, $offset);
        list($offset, $s) = self::readDER($der, $offset);

        // Convert r-value and s-value from signed two's compliment to unsigned
        // big-endian integers
        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        // Pad out r and s so that they are $keySize bits long
        $r = str_pad($r, $keySize / 8, "\x00", STR_PAD_LEFT);
        $s = str_pad($s, $keySize / 8, "\x00", STR_PAD_LEFT);

        return $r . $s;
    }

    /**
     * Encodes a value into a DER object.
     *
     * @param   int     $type DER tag
     * @param   string  $value the value to encode
     *
     * @return  string  the encoded object
     */
    private static function encodeDER(int $type, string $value): string
    {
        $tag_header = 0;

        if ($type === self::ASN1_SEQUENCE) {
            $tag_header |= 0x20;
        }

        // Type
        $der = chr($tag_header | $type);

        // Length
        $der .= chr(strlen($value));

        return $der . $value;
    }

    /**
     * Reads binary DER-encoded data and decodes into a single object
     *
     * @param string $der the binary data in DER format
     * @param int $offset the offset of the data stream containing the object
     * to decode
     *
     * @return array{int, string|null} the new offset and the decoded object
     */
    private static function readDER(string $der, int $offset = 0): array
    {
        $pos = $offset;
        $size = strlen($der);
        $constructed = (ord($der[$pos]) >> 5) & 0x01;
        $type = ord($der[$pos++]) & 0x1f;

        // Length
        $len = ord($der[$pos++]);

        if ($len & 0x80) {
            $n = $len & 0x1f;
            $len = 0;
            while ($n-- && $pos < $size) {
                $len = ($len << 8) | ord($der[$pos++]);
            }
        }

        // Value
        if ($type == self::ASN1_BIT_STRING) {
            $pos++; // Skip the first contents octet (padding indicator)
            $data = substr($der, $pos, $len - 1);
            $pos += $len - 1;
        } elseif (!$constructed) {
            $data = substr($der, $pos, $len);
            $pos += $len;
        } else {
            $data = null;
        }

        return [$pos, $data];
    }
}
