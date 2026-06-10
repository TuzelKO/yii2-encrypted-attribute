# Yii2 Encrypted Attribute extension

[![Project Status: Active](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![Tests](https://github.com/TuzelKO/yii2-encrypted-attribute/actions/workflows/tests.yml/badge.svg)](https://github.com/TuzelKO/yii2-encrypted-attribute/actions/workflows/tests.yml)
[![Latest Version](https://img.shields.io/packagist/v/tuzelko/yii2-encrypted-attribute)](https://packagist.org/packages/tuzelko/yii2-encrypted-attribute)
[![PHP Version](https://img.shields.io/packagist/dependency-v/tuzelko/yii2-encrypted-attribute/php)](https://packagist.org/packages/tuzelko/yii2-encrypted-attribute)
[![Total Downloads](https://img.shields.io/packagist/dt/tuzelko/yii2-encrypted-attribute)](https://packagist.org/packages/tuzelko/yii2-encrypted-attribute)
[![License](https://img.shields.io/github/license/TuzelKO/yii2-encrypted-attribute)](https://github.com/TuzelKO/yii2-encrypted-attribute/blob/main/LICENSE)

Transparent at-rest encryption for [Yii2](https://www.yiiframework.com/) `ActiveRecord` attributes with pluggable ciphers (libsodium secretbox or AES-256-GCM via openssl, the choice is always explicit).

The physical attribute always holds ciphertext; plain values are accessed through a virtual `{attribute}_decrypted` sibling. The model can therefore be serialized to cache, logged, or dumped without ever exposing plaintext — and the encryption key is never stored on the model or the behavior.

## Features

- **Virtual accessors** — `$model->secret_decrypted = 'raw'` encrypts; reading it decrypts; the `secret` column only ever sees ciphertext
- **Authenticated encryption only** — tampered ciphertext fails loudly, never decrypts to garbage
- **Pluggable ciphers** — XSalsa20-Poly1305 secretbox or AES-256-GCM, always an explicit choice; custom algorithms via one interface
- **Random nonce per write** — equal plaintexts produce different ciphertexts
- **Cache-safe** — serialized models carry neither plaintext nor key material
- **Key management included** — keys are resolved by name from [tuzelko/yii2-key-storage](https://github.com/TuzelKO/yii2-key-storage) via the DI container
- **Multiple attributes, configurable suffix** — one behavior covers any number of columns

## Requirements

- PHP >= 8.0
- ext-sodium (`SodiumSecretboxCipher`) **or** ext-openssl (`AesGcmCipher`) — checked lazily, only the extension of the cipher you actually use is needed
- yiisoft/yii2 ~2.0
- tuzelko/yii2-key-storage ^1.0 (installed automatically)

## Installation

```bash
composer require tuzelko/yii2-encrypted-attribute
```

## Quick start

### 1. Register a key provider in the DI container

```php
// config/main.php
use tuzelko\yii\keystorage\KeyProviderInterface;
use tuzelko\yii\keystorage\KeyStorage;
use tuzelko\yii\keystorage\types\SodiumSecretboxKey;

'container' => [
    'singletons' => [
        KeyProviderInterface::class => static fn () => new KeyStorage([
            'keys' => [
                'appCrypto' => [
                    'base64' => getenv('APP_CRYPTO_KEY'), // 32 bytes, base64-encoded
                    'type'   => SodiumSecretboxKey::class,
                ],
            ],
        ]),
    ],
],
```

Generate a key:

```bash
php -r "echo base64_encode(random_bytes(32)), PHP_EOL;"
```

### 2. Attach the behavior

The encrypted column must be a `TEXT`/`VARCHAR` (the stored value is base64).

```php
use tuzelko\yii\encryptedattribute\ciphers\SodiumSecretboxCipher;
use tuzelko\yii\encryptedattribute\EncryptedAttributeBehavior;
use yii\db\ActiveRecord;

class Integration extends ActiveRecord
{
    public function behaviors(): array
    {
        return [
            [
                'class'      => EncryptedAttributeBehavior::class,
                'keyName'    => 'appCrypto',
                'attributes' => ['api_token', 'api_secret'],
                'cipher'     => SodiumSecretboxCipher::class,
            ],
        ];
    }
}
```

### 3. Use the virtual accessors

```php
$integration = new Integration();
$integration->api_token_decrypted = $rawToken;   // encrypted on assignment
$integration->save();

echo $integration->api_token_decrypted;          // decrypted on read
echo $integration->api_token;                    // base64(nonce || ciphertext) — safe to log

$integration->api_token_decrypted = null;        // clears the column
```

## Configuration

| Property | Type | Default | Description |
|---|---|---|---|
| `attributes` | `array` | `[]` | Physical column names to virtualize |
| `keyName` | `string` | — *(required)* | Key name resolved through `KeyProviderInterface::getRaw()` |
| `suffix` | `string` | `'_decrypted'` | Suffix of the virtual accessor |
| `cipher` | `CipherInterface\|class-string` | — *(required)* | Encryption algorithm (see [Ciphers](#ciphers)) |

## Ciphers

There is intentionally **no default cipher** — the algorithm a model uses must be visible in its configuration.

| Cipher | Algorithm | Requires | Key | Stored format |
|---|---|---|---|---|
| `SodiumSecretboxCipher` | XSalsa20-Poly1305 | ext-sodium | 32 bytes | `base64(nonce[24] \|\| ciphertext)` |
| `XChaCha20Poly1305Cipher` | XChaCha20-Poly1305 (IETF) | ext-sodium | 32 bytes | `base64(nonce[24] \|\| ciphertext)` |
| `AesGcmCipher` | AES-256-GCM | ext-openssl | 32 bytes | `base64(nonce[12] \|\| tag[16] \|\| ciphertext)` |

All three are authenticated (AEAD) and use a fresh random nonce per write; nonce sizes are collision-safe for random generation. Algorithms with short nonces unsafe for random use (ChaCha20-Poly1305 IETF) or without built-in authentication (AES-CBC) are intentionally not shipped.

```php
use tuzelko\yii\encryptedattribute\ciphers\AesGcmCipher;

[
    'class'      => EncryptedAttributeBehavior::class,
    'keyName'    => 'appCrypto',
    'attributes' => ['api_token'],
    'cipher'     => AesGcmCipher::class,
]
```

The extension check happens lazily, when the cipher is first used — environments without ext-sodium can install the package and use `AesGcmCipher` freely.

A custom algorithm is a class implementing `CipherInterface` (`encrypt`/`decrypt`, authenticated encryption with a fresh random nonce per call).

> **Note:** the stored value does not identify the cipher that produced it. The cipher choice is deliberately explicit configuration, never auto-detected from the environment — otherwise the same model could silently encrypt differently on different hosts. Switching ciphers requires re-encrypting existing rows (same procedure as [key rotation](#key-rotation)).

## How it works

- **Stored format**: base64 blob of nonce and ciphertext (exact layout per cipher, see [Ciphers](#ciphers)); the nonce is generated fresh for every assignment.
- **Key resolution is lazy**: the key is fetched from the container-registered `KeyProviderInterface` at encrypt/decrypt time, never kept on the behavior or the owner. A model serialized into Redis/Valkey (or any cache) contains only ciphertext.
- **Authentication**: secretbox is authenticated encryption — any modification of the stored value raises a `RuntimeException` (`authentication tag mismatch`) instead of returning corrupted plaintext.

## Why the key cannot be passed directly

The behavior deliberately accepts only a key **name** — there is no `key` property and never will be. This is not an inconvenience, it is the security model:

In Yii2, behaviors are serialized together with their owner. If the raw key (or anything that memoizes it) lived on the behavior, then every `serialize($model)` — caching an AR model in Redis/Valkey, storing it in a session, queueing it in a job payload — would write the encryption key right next to the ciphertext it protects. One `KEYS *` away from a full decrypt.

With the key-storage indirection the serialized model carries only the key *name* (a meaningless string), while the actual bytes live in the [tuzelko/yii2-key-storage](https://github.com/TuzelKO/yii2-key-storage) component inside the DI container and are resolved at encrypt/decrypt time. The test suite asserts this invariant: a serialized model contains neither plaintext nor key material.

## Searching and indexing

Ciphertexts are randomized, so encrypted columns **cannot be searched, compared, or indexed** by plaintext. Keep values that must be queryable out of `attributes`, or store a separate deterministic digest (e.g. HMAC) alongside for lookups.

## Key rotation

The behavior intentionally has no multi-key fallback. To rotate a key: add the new key under a new name, re-encrypt existing rows (`read with old keyName → write with new keyName`), then drop the old key. Doing this in a console migration keeps the window where both keys exist explicit and short.

## Error handling

| Condition | Result |
|---|---|
| `keyName` or `cipher` not configured | `yii\base\InvalidConfigException` on behavior init |
| Key unknown / malformed / wrong length | `tuzelko\yii\keystorage\InvalidKeyException` |
| Tampered or corrupted ciphertext | `RuntimeException` (authentication tag mismatch) |

## Running tests

```bash
make test
```

Tests run inside Docker (PHP 8.3 + SQLite) with no local setup required.

## License

MIT — see [LICENSE](LICENSE).