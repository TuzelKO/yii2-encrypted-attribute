<?php

namespace tuzelko\yii\encryptedattribute\ciphers;

use RuntimeException;

/**
 * AES-256-GCM authenticated encryption via ext-openssl, for environments
 * without ext-sodium.
 *
 * Stored format: base64(nonce || tag || ciphertext), standard base64.
 * Key: 32 raw bytes (use CustomLengthKey(32) or SodiumSecretboxKey in
 * tuzelko/yii2-key-storage — both validate 32 bytes).
 *
 * Requires ext-openssl.
 */
class AesGcmCipher implements CipherInterface
{
    private const ALGO         = 'aes-256-gcm';
    private const NONCE_LENGTH = 12;
    private const TAG_LENGTH   = 16;

    public function __construct()
    {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException(self::class . ' requires ext-openssl.');
        }
    }

    public function encrypt(string $plaintext, string $key): string
    {
        $nonce = random_bytes(self::NONCE_LENGTH);
        $tag   = '';

        $ciphertext = openssl_encrypt($plaintext, self::ALGO, $key, OPENSSL_RAW_DATA, $nonce, $tag, '', self::TAG_LENGTH);

        if ($ciphertext === false) {
            throw new RuntimeException('Failed to encrypt attribute: ' . openssl_error_string());
        }

        return base64_encode($nonce . $tag . $ciphertext);
    }

    public function decrypt(string $encoded, string $key): string
    {
        $blob = base64_decode($encoded, true);

        if ($blob === false || strlen($blob) < self::NONCE_LENGTH + self::TAG_LENGTH) {
            throw new RuntimeException('Failed to decrypt attribute: value is malformed.');
        }

        $nonce      = substr($blob, 0, self::NONCE_LENGTH);
        $tag        = substr($blob, self::NONCE_LENGTH, self::TAG_LENGTH);
        $ciphertext = substr($blob, self::NONCE_LENGTH + self::TAG_LENGTH);

        $plaintext = openssl_decrypt($ciphertext, self::ALGO, $key, OPENSSL_RAW_DATA, $nonce, $tag);

        if ($plaintext === false) {
            throw new RuntimeException('Failed to decrypt attribute: authentication tag mismatch.');
        }

        return $plaintext;
    }
}