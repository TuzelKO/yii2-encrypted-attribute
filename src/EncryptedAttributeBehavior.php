<?php

namespace tuzelko\yii\encryptedattribute;

use tuzelko\yii\encryptedattribute\ciphers\CipherInterface;
use tuzelko\yii\keystorage\KeyProviderInterface;
use Yii;
use yii\base\Behavior;
use yii\base\InvalidConfigException;
use yii\db\ActiveRecord;

/**
 * Transparent encryption for AR attributes via virtual `{attribute}_decrypted` accessors.
 *
 * Physical AR attributes always hold the encrypted value (base64; exact format is
 * defined by the cipher). Access plain values through the virtual `_decrypted` sibling:
 *
 *   $model->secret_decrypted = 'raw value';  // encrypts → stores in $model->secret
 *   echo $model->secret_decrypted;           // reads $model->secret → decrypts → returns raw
 *
 * This ensures the model can be serialized to cache without exposing plain values.
 *
 * Configuration:
 *
 *   [
 *       'class'      => EncryptedAttributeBehavior::class,
 *       'keyName'    => 'appCrypto',
 *       'attributes' => ['secret_column'],
 *       'cipher'     => SomeCipher::class,             // any CipherInterface implementation
 *       // Per-call cipher options, keyed by the chosen cipher's OPTION_* constants.
 *       // Closures are resolved per operation with ($owner, $attribute):
 *       'cipherOptions' => [
 *           SomeCipher::OPTION_FOO => static fn ($owner, string $attribute): string
 *               => $owner::tableName() . '.' . $attribute,
 *       ],
 *   ]
 *
 * The raw key is resolved lazily from the KeyProviderInterface registered in the DI container
 * (see tuzelko/yii2-key-storage) and is never stored on the behavior — a cached owner model
 * serialized to Redis/Valkey does not carry the key.
 *
 * @property ActiveRecord $owner
 */
class EncryptedAttributeBehavior extends Behavior
{
    public array  $attributes = [];
    public string $keyName    = '';
    public string $suffix     = '_decrypted';

    /**
     * Encryption algorithm: a CipherInterface class name or instance. Required —
     * the cipher is always an explicit choice, never a default, so the algorithm
     * a model uses is visible in its configuration. Ciphers are stateless; the
     * stored value does not identify the cipher, so switching it requires
     * re-encrypting existing rows.
     *
     * @var CipherInterface|class-string<CipherInterface>|null
     */
    public $cipher = null;

    /**
     * Per-call cipher options, keyed by the configured cipher's OPTION_* constants.
     * A Closure value is resolved on every operation with ($owner, $attribute) —
     * use it for context-dependent values such as associated data. The same
     * resolved options must reproduce on decrypt (don't bind to mutable state).
     *
     * The behavior passes options through as-is; validation is the cipher's job.
     *
     * @var array<string, mixed>
     */
    public array $cipherOptions = [];

    private ?CipherInterface $cipherInstance = null;

    /**
     * @throws InvalidConfigException
     */
    public function init(): void
    {
        parent::init();

        if ($this->keyName === '') {
            throw new InvalidConfigException(self::class . ': $keyName must be set.');
        }

        $validCipher = $this->cipher instanceof CipherInterface
            || (is_string($this->cipher) && is_subclass_of($this->cipher, CipherInterface::class));

        if (!$validCipher) {
            throw new InvalidConfigException(
                self::class . ': $cipher must be set to a ' . CipherInterface::class . ' instance or class name.'
            );
        }
    }

    /**
     * Resolves raw key bytes from the key provider on demand. The provider memoizes the
     * decoded bytes itself, so the key lives only there — never on this behavior or the
     * owner model (hence never in a serialized cache entry).
     *
     * @throws InvalidConfigException
     */
    private function key(): string
    {
        return Yii::$container->get(KeyProviderInterface::class)->getRaw($this->keyName);
    }

    /**
     * Lazily instantiates the configured cipher. Instantiation (and therefore
     * the cipher's PHP-extension check) is deferred to first use, so attaching
     * the behavior never fails on a missing extension.
     */
    private function cipher(): CipherInterface
    {
        if ($this->cipherInstance === null) {
            $this->cipherInstance = $this->cipher instanceof CipherInterface
                ? $this->cipher
                : new ($this->cipher)();
        }

        return $this->cipherInstance;
    }

    public function canGetProperty($name, $checkVars = true): bool
    {
        return $this->isVirtual($name) || parent::canGetProperty($name, $checkVars);
    }

    public function canSetProperty($name, $checkVars = true): bool
    {
        return $this->isVirtual($name) || parent::canSetProperty($name, $checkVars);
    }

    public function __isset($name): bool
    {
        if ($this->isVirtual($name)) {
            return $this->owner->getAttribute($this->physical($name)) !== null;
        }
        return parent::__isset($name);
    }

    public function __get($name)
    {
        if ($this->isVirtual($name)) {
            $physical  = $this->physical($name);
            $encrypted = $this->owner->getAttribute($physical);
            return $encrypted !== null
                ? $this->cipher()->decrypt($encrypted, $this->key(), $this->options($physical))
                : null;
        }
        return parent::__get($name);
    }

    public function __set($name, $value): void
    {
        if ($this->isVirtual($name)) {
            $physical = $this->physical($name);
            $this->owner->setAttribute(
                $physical,
                $value !== null ? $this->cipher()->encrypt($value, $this->key(), $this->options($physical)) : null,
            );
            return;
        }
        parent::__set($name, $value);
    }

    /**
     * Resolves cipherOptions for the given physical attribute: Closure values
     * are called with ($owner, $attribute), everything else passes through.
     *
     * @return array<string, mixed>
     */
    private function options(string $attribute): array
    {
        $resolved = [];
        foreach ($this->cipherOptions as $key => $value) {
            $resolved[$key] = $value instanceof \Closure ? $value($this->owner, $attribute) : $value;
        }
        return $resolved;
    }

    private function isVirtual(string $name): bool
    {
        return str_ends_with($name, $this->suffix)
            && in_array($this->physical($name), $this->attributes, true);
    }

    private function physical(string $name): string
    {
        return substr($name, 0, -strlen($this->suffix));
    }
}