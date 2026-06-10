<?php

namespace tuzelko\yii\encryptedattribute\ciphers;

use RuntimeException;

/**
 * XSalsa20-Poly1305 authenticated encryption via sodium_crypto_secretbox.
 *
 * Stored format: base64(nonce || ciphertext), SODIUM_BASE64_VARIANT_ORIGINAL.
 * Key: 32 raw bytes (SodiumSecretboxKey in tuzelko/yii2-key-storage).
 *
 * Requires ext-sodium.
 */
class SodiumSecretboxCipher implements CipherInterface
{
    public function __construct()
    {
        if (!extension_loaded('sodium')) {
            throw new RuntimeException(self::class . ' requires ext-sodium.');
        }
    }

    /**
     * @throws \SodiumException
     */
    public function encrypt(string $plaintext, string $key): string
    {
        $nonce      = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);

        return sodium_bin2base64($nonce . $ciphertext, SODIUM_BASE64_VARIANT_ORIGINAL);
    }

    /**
     * @throws \SodiumException
     */
    public function decrypt(string $encoded, string $key): string
    {
        $blob = sodium_base642bin($encoded, SODIUM_BASE64_VARIANT_ORIGINAL);

        if (strlen($blob) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new RuntimeException('Failed to decrypt attribute: value is malformed.');
        }

        $nonce      = substr($blob, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = substr($blob, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);

        if ($plaintext === false) {
            throw new RuntimeException('Failed to decrypt attribute: authentication tag mismatch.');
        }

        return $plaintext;
    }
}