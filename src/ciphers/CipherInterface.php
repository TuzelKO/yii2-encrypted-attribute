<?php

namespace tuzelko\yii\encryptedattribute\ciphers;

use RuntimeException;

/**
 * Contract for attribute encryption algorithms.
 *
 * Implementations must use authenticated encryption and a fresh random nonce
 * per encrypt() call, and must return a storable text value (base64).
 *
 * The stored value does not identify the cipher that produced it: decrypting
 * with a different cipher (or key) must fail with an exception, never return
 * corrupted plaintext.
 */
interface CipherInterface
{
    /**
     * Encrypts plaintext with the given raw key, returns a storable text value.
     */
    public function encrypt(string $plaintext, string $key): string;

    /**
     * Decrypts a value previously produced by encrypt() with the same key.
     *
     * @throws RuntimeException when the value is malformed, tampered with,
     *                          or was encrypted with a different key/cipher.
     */
    public function decrypt(string $encoded, string $key): string;
}