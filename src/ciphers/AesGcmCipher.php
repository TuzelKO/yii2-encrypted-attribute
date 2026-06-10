<?php

namespace tuzelko\yii\encryptedattribute\ciphers;

use RuntimeException;

/**
 * AES-256-GCM authenticated encryption via ext-openssl, for environments
 * without ext-sodium.
 *
 * Options:
 *   OPTION_AD — associated data (string): authenticated but not encrypted
 *   context the ciphertext is bound to; decryption must supply the same value.
 *
 * Stored format: base64(nonce || tag || ciphertext), standard base64.
 * Key: 32 raw bytes (use CustomLengthKey(32) or SodiumSecretboxKey in
 * tuzelko/yii2-key-storage — both validate 32 bytes).
 *
 * Requires ext-openssl.
 */
class AesGcmCipher extends AbstractCipher
{
    public const OPTION_AD = 'ad';

    private const ALGO         = 'aes-256-gcm';
    private const NONCE_LENGTH = 12;
    private const TAG_LENGTH   = 16;

    public function __construct()
    {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException(self::class . ' requires ext-openssl.');
        }
    }

    protected function supportedOptions(): array
    {
        return [self::OPTION_AD];
    }

    public function encrypt(string $plaintext, string $key, array $options = []): string
    {
        $this->validateOptions($options);
        $ad = $this->stringOption($options, self::OPTION_AD);

        $nonce = random_bytes(self::NONCE_LENGTH);
        $tag   = '';

        $ciphertext = openssl_encrypt($plaintext, self::ALGO, $key, OPENSSL_RAW_DATA, $nonce, $tag, $ad, self::TAG_LENGTH);

        if ($ciphertext === false) {
            throw new RuntimeException('Failed to encrypt attribute: ' . openssl_error_string());
        }

        return base64_encode($nonce . $tag . $ciphertext);
    }

    public function decrypt(string $encoded, string $key, array $options = []): string
    {
        $this->validateOptions($options);
        $ad = $this->stringOption($options, self::OPTION_AD);

        $blob = base64_decode($encoded, true);

        if ($blob === false || strlen($blob) < self::NONCE_LENGTH + self::TAG_LENGTH) {
            throw new RuntimeException('Failed to decrypt attribute: value is malformed.');
        }

        $nonce      = substr($blob, 0, self::NONCE_LENGTH);
        $tag        = substr($blob, self::NONCE_LENGTH, self::TAG_LENGTH);
        $ciphertext = substr($blob, self::NONCE_LENGTH + self::TAG_LENGTH);

        $plaintext = openssl_decrypt($ciphertext, self::ALGO, $key, OPENSSL_RAW_DATA, $nonce, $tag, $ad);

        if ($plaintext === false) {
            throw new RuntimeException('Failed to decrypt attribute: authentication tag mismatch.');
        }

        return $plaintext;
    }
}