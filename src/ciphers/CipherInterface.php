<?php

namespace tuzelko\yii\encryptedattribute\ciphers;

use InvalidArgumentException;
use RuntimeException;

/**
 * Contract for attribute encryption algorithms.
 *
 * Implementations must use authenticated encryption and a fresh random nonce
 * per encrypt() call, and must return a storable text value (base64).
 *
 * Per-call parameters are passed via $options. Each cipher declares the keys
 * it understands as its own OPTION_* class constants — option support is a
 * property of the concrete algorithm, not of this contract. Implementations
 * must reject unknown option keys with an exception, never ignore them
 * silently: a silently dropped option is a silently weakened guarantee.
 *
 * The stored value does not identify the cipher that produced it: decrypting
 * with a different cipher, key, or options must fail with an exception,
 * never return corrupted plaintext.
 */
interface CipherInterface
{
    /**
     * Encrypts plaintext with the given raw key, returns a storable text value.
     *
     * @param array<string, mixed> $options per-call parameters, keyed by the cipher's OPTION_* constants
     * @throws InvalidArgumentException on unknown option keys or invalid option values.
     */
    public function encrypt(string $plaintext, string $key, array $options = []): string;

    /**
     * Decrypts a value previously produced by encrypt() with the same key and options.
     *
     * @param array<string, mixed> $options per-call parameters, keyed by the cipher's OPTION_* constants
     * @throws InvalidArgumentException on unknown option keys or invalid option values.
     * @throws RuntimeException when the value is malformed, tampered with, or was
     *                          encrypted with a different key/cipher/options.
     */
    public function decrypt(string $encoded, string $key, array $options = []): string;
}