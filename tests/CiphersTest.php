<?php

namespace tuzelko\yii\encryptedattribute\tests;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use tuzelko\yii\encryptedattribute\ciphers\AesGcmCipher;
use tuzelko\yii\encryptedattribute\ciphers\CipherInterface;
use tuzelko\yii\encryptedattribute\ciphers\SodiumSecretboxCipher;
use tuzelko\yii\encryptedattribute\ciphers\XChaCha20Poly1305Cipher;

class CiphersTest extends TestCase
{
    private const KEY       = '0123456789abcdef0123456789abcdef';
    private const OTHER_KEY = 'fedcba9876543210fedcba9876543210';

    public function cipherProvider(): array
    {
        return [
            'sodium secretbox'    => [new SodiumSecretboxCipher()],
            'aes-256-gcm'         => [new AesGcmCipher()],
            'xchacha20-poly1305'  => [new XChaCha20Poly1305Cipher()],
        ];
    }

    /**
     * @dataProvider cipherProvider
     */
    public function testRoundtrip(CipherInterface $cipher): void
    {
        $encoded = $cipher->encrypt('plain value', self::KEY);

        $this->assertNotSame('plain value', $encoded);
        $this->assertStringNotContainsString('plain value', $encoded);
        $this->assertSame('plain value', $cipher->decrypt($encoded, self::KEY));
    }

    /**
     * @dataProvider cipherProvider
     */
    public function testEncryptionIsRandomized(CipherInterface $cipher): void
    {
        $this->assertNotSame(
            $cipher->encrypt('same value', self::KEY),
            $cipher->encrypt('same value', self::KEY),
        );
    }

    /**
     * @dataProvider cipherProvider
     */
    public function testWrongKeyIsRejected(CipherInterface $cipher): void
    {
        $encoded = $cipher->encrypt('plain value', self::KEY);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('authentication tag mismatch');
        $cipher->decrypt($encoded, self::OTHER_KEY);
    }

    /**
     * @dataProvider cipherProvider
     */
    public function testTamperedCiphertextIsRejected(CipherInterface $cipher): void
    {
        $encoded = $cipher->encrypt('plain value', self::KEY);

        $blob = base64_decode($encoded);
        $last = strlen($blob) - 1;
        $blob[$last] = $blob[$last] === 'x' ? 'y' : 'x';

        $this->expectException(RuntimeException::class);
        $cipher->decrypt(base64_encode($blob), self::KEY);
    }

    /**
     * @dataProvider cipherProvider
     */
    public function testTooShortBlobIsRejectedAsMalformed(CipherInterface $cipher): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('malformed');
        $cipher->decrypt(base64_encode('tiny'), self::KEY);
    }

    /**
     * @dataProvider cipherProvider
     */
    public function testEmptyStringRoundtrip(CipherInterface $cipher): void
    {
        $this->assertSame('', $cipher->decrypt($cipher->encrypt('', self::KEY), self::KEY));
    }

    /**
     * @dataProvider cipherProvider
     */
    public function testBinaryPlaintextRoundtrip(CipherInterface $cipher): void
    {
        $binary = random_bytes(256);

        $this->assertSame($binary, $cipher->decrypt($cipher->encrypt($binary, self::KEY), self::KEY));
    }

    public function testCiphersAreNotInterchangeable(): void
    {
        $encoded = (new SodiumSecretboxCipher())->encrypt('plain value', self::KEY);

        $this->expectException(RuntimeException::class);
        (new AesGcmCipher())->decrypt($encoded, self::KEY);
    }

    public function testSodiumCiphersAreNotInterchangeable(): void
    {
        // Same key size, same nonce size, same stored layout — must still fail on the tag.
        $encoded = (new SodiumSecretboxCipher())->encrypt('plain value', self::KEY);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('authentication tag mismatch');
        (new XChaCha20Poly1305Cipher())->decrypt($encoded, self::KEY);
    }
}