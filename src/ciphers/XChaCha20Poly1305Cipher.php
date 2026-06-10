<?php

namespace tuzelko\yii\encryptedattribute\ciphers;

use RuntimeException;

/**
 * XChaCha20-Poly1305 (IETF) authenticated encryption via
 * sodium_crypto_aead_xchacha20poly1305_ietf — libsodium's recommended AEAD
 * for new designs; the 24-byte nonce is safe to generate randomly.
 *
 * Options:
 *   OPTION_AD — associated data (string): authenticated but not encrypted
 *   context the ciphertext is bound to; decryption must supply the same value.
 *
 * Stored format: base64(nonce || ciphertext), SODIUM_BASE64_VARIANT_ORIGINAL.
 * Key: 32 raw bytes (SodiumSecretboxKey in tuzelko/yii2-key-storage validates 32 bytes).
 *
 * Requires ext-sodium.
 */
class XChaCha20Poly1305Cipher extends AbstractCipher
{
    public const OPTION_AD = 'ad';

    public function __construct()
    {
        if (!extension_loaded('sodium')) {
            throw new RuntimeException(self::class . ' requires ext-sodium.');
        }
    }

    protected function supportedOptions(): array
    {
        return [self::OPTION_AD];
    }

    /**
     * @throws \SodiumException
     */
    public function encrypt(string $plaintext, string $key, array $options = []): string
    {
        $this->validateOptions($options);
        $ad = $this->stringOption($options, self::OPTION_AD);

        $nonce      = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $ad, $nonce, $key);

        return sodium_bin2base64($nonce . $ciphertext, SODIUM_BASE64_VARIANT_ORIGINAL);
    }

    /**
     * @throws \SodiumException
     */
    public function decrypt(string $encoded, string $key, array $options = []): string
    {
        $this->validateOptions($options);
        $ad = $this->stringOption($options, self::OPTION_AD);

        $blob = sodium_base642bin($encoded, SODIUM_BASE64_VARIANT_ORIGINAL);

        if (strlen($blob) <= SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES) {
            throw new RuntimeException('Failed to decrypt attribute: value is malformed.');
        }

        $nonce      = substr($blob, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ciphertext = substr($blob, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $ad, $nonce, $key);

        if ($plaintext === false) {
            throw new RuntimeException('Failed to decrypt attribute: authentication tag mismatch.');
        }

        return $plaintext;
    }
}