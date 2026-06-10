<?php

namespace tuzelko\yii\encryptedattribute\ciphers;

use InvalidArgumentException;

/**
 * Shared strict option handling.
 *
 * A concrete cipher declares the option keys it understands via
 * supportedOptions(); anything else is rejected with an exception —
 * silently ignoring an option would silently weaken the produced guarantee.
 */
abstract class AbstractCipher implements CipherInterface
{
    /**
     * Option keys (OPTION_* constant values) this cipher understands.
     *
     * @return string[]
     */
    protected function supportedOptions(): array
    {
        return [];
    }

    /**
     * @param array<string, mixed> $options
     * @throws InvalidArgumentException on unknown option keys.
     */
    protected function validateOptions(array $options): void
    {
        $unknown = array_diff(array_keys($options), $this->supportedOptions());

        if ($unknown !== []) {
            $supported = $this->supportedOptions();
            throw new InvalidArgumentException(sprintf(
                '%s: unknown option(s): %s. Supported: %s.',
                static::class,
                implode(', ', $unknown),
                $supported === [] ? '(none)' : implode(', ', $supported),
            ));
        }
    }

    /**
     * Returns a string option value, '' when not set.
     *
     * @param array<string, mixed> $options
     * @throws InvalidArgumentException when the value is not a string.
     */
    protected function stringOption(array $options, string $key): string
    {
        $value = $options[$key] ?? '';

        if (!is_string($value)) {
            throw new InvalidArgumentException(static::class . ": option \"$key\" must be a string.");
        }

        return $value;
    }
}