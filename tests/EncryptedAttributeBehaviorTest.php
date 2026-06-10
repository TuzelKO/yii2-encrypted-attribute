<?php

namespace tuzelko\yii\encryptedattribute\tests;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use tuzelko\yii\encryptedattribute\EncryptedAttributeBehavior;
use tuzelko\yii\encryptedattribute\tests\fixtures\Vault;
use tuzelko\yii\keystorage\InvalidKeyException;
use tuzelko\yii\keystorage\KeyProviderInterface;
use tuzelko\yii\keystorage\KeyStorage;
use tuzelko\yii\keystorage\types\SodiumSecretboxKey;
use yii\base\InvalidConfigException;

class EncryptedAttributeBehaviorTest extends TestCase
{
    private const RAW_KEY = '0123456789abcdef0123456789abcdef';

    protected function setUp(): void
    {
        parent::setUp();

        \Yii::$container->setSingleton(KeyProviderInterface::class, static fn () => new KeyStorage([
            'keys' => [
                'main' => ['base64' => base64_encode(self::RAW_KEY), 'type' => SodiumSecretboxKey::class],
            ],
        ]));

        \Yii::$app->db->createCommand('DELETE FROM vault')->execute();
    }

    protected function tearDown(): void
    {
        \Yii::$container->clear(KeyProviderInterface::class);
        parent::tearDown();
    }

    // -------------------------------------------------------------------------
    // Virtual accessors
    // -------------------------------------------------------------------------

    public function testSetStoresEncryptedValueInPhysicalAttribute(): void
    {
        $model = new Vault();
        $model->secret_decrypted = 'top secret';

        $this->assertNotNull($model->secret);
        $this->assertNotSame('top secret', $model->secret);
        $this->assertStringNotContainsString('top secret', $model->secret);

        // Stored format: base64(nonce || ciphertext), nonce is 24 bytes.
        $blob = sodium_base642bin($model->secret, SODIUM_BASE64_VARIANT_ORIGINAL);
        $this->assertGreaterThan(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, strlen($blob));
    }

    public function testGetDecryptsBackToOriginalValue(): void
    {
        $model = new Vault();
        $model->secret_decrypted = 'top secret';

        $this->assertSame('top secret', $model->secret_decrypted);
    }

    public function testNullRoundtrip(): void
    {
        $model = new Vault();
        $model->secret_decrypted = null;

        $this->assertNull($model->secret);
        $this->assertNull($model->secret_decrypted);
        $this->assertFalse(isset($model->secret_decrypted));
    }

    public function testIssetReflectsPhysicalAttribute(): void
    {
        $model = new Vault();
        $this->assertFalse(isset($model->secret_decrypted));

        $model->secret_decrypted = 'x';
        $this->assertTrue(isset($model->secret_decrypted));
    }

    public function testAttributesAreEncryptedIndependently(): void
    {
        $model = new Vault();
        $model->secret_decrypted = 'one';
        $model->token_decrypted  = 'two';

        $this->assertSame('one', $model->secret_decrypted);
        $this->assertSame('two', $model->token_decrypted);
        $this->assertNotSame($model->secret, $model->token);
    }

    public function testNonConfiguredAttributeIsNotVirtualized(): void
    {
        $model = new Vault();

        $this->expectException(\yii\base\UnknownPropertyException::class);
        $model->note_decrypted = 'plain';
    }

    public function testEncryptionIsRandomized(): void
    {
        // Fresh random nonce per encryption: same plaintext must not produce equal ciphertexts.
        $a = new Vault();
        $b = new Vault();
        $a->secret_decrypted = 'same value';
        $b->secret_decrypted = 'same value';

        $this->assertNotSame($a->secret, $b->secret);
    }

    // -------------------------------------------------------------------------
    // Persistence
    // -------------------------------------------------------------------------

    public function testValueSurvivesSaveAndReload(): void
    {
        $model = new Vault();
        $model->secret_decrypted = 'persisted secret';
        $this->assertTrue($model->save());

        $reloaded = Vault::findOne($model->id);
        $this->assertSame('persisted secret', $reloaded->secret_decrypted);
    }

    public function testDatabaseRowHoldsCiphertextOnly(): void
    {
        $model = new Vault();
        $model->secret_decrypted = 'persisted secret';
        $model->save();

        $rawColumn = \Yii::$app->db
            ->createCommand('SELECT secret FROM vault WHERE id = :id', [':id' => $model->id])
            ->queryScalar();

        $this->assertStringNotContainsString('persisted secret', $rawColumn);
    }

    public function testSerializedModelCarriesNeitherPlaintextNorKey(): void
    {
        $model = new Vault();
        $model->secret_decrypted = 'cache me if you can';

        $serialized = serialize($model);

        $this->assertStringNotContainsString('cache me if you can', $serialized);
        $this->assertStringNotContainsString(self::RAW_KEY, $serialized);
    }

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    public function testTamperedCiphertextIsRejected(): void
    {
        $model = new Vault();
        $model->secret_decrypted = 'integrity matters';

        $blob = sodium_base642bin($model->secret, SODIUM_BASE64_VARIANT_ORIGINAL);
        $blob[strlen($blob) - 1] = $blob[-1] === 'x' ? 'y' : 'x'; // flip the last ciphertext byte
        $model->secret = sodium_bin2base64($blob, SODIUM_BASE64_VARIANT_ORIGINAL);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('authentication tag mismatch');
        $model->secret_decrypted;
    }

    public function testMissingKeyNameIsRejectedOnInit(): void
    {
        $this->expectException(InvalidConfigException::class);
        new EncryptedAttributeBehavior(['attributes' => ['secret']]);
    }

    public function testMissingCipherIsRejectedOnInit(): void
    {
        $this->expectException(InvalidConfigException::class);
        $this->expectExceptionMessage('$cipher must be set');
        new EncryptedAttributeBehavior(['keyName' => 'main', 'attributes' => ['secret']]);
    }

    public function testUnknownKeyNameBubblesUpFromProvider(): void
    {
        $model = new Vault();
        $model->detachBehavior('encryption');
        $model->attachBehavior('encryption', [
            'class'      => EncryptedAttributeBehavior::class,
            'keyName'    => 'missing',
            'attributes' => ['secret'],
            'cipher'     => \tuzelko\yii\encryptedattribute\ciphers\SodiumSecretboxCipher::class,
        ]);

        $this->expectException(InvalidKeyException::class);
        $model->secret_decrypted = 'boom';
    }

    // -------------------------------------------------------------------------
    // Cipher selection
    // -------------------------------------------------------------------------

    public function testAlternativeCipherWorksEndToEnd(): void
    {
        $model = new Vault();
        $model->detachBehavior('encryption');
        $model->attachBehavior('encryption', [
            'class'      => EncryptedAttributeBehavior::class,
            'keyName'    => 'main',
            'attributes' => ['secret'],
            'cipher'     => \tuzelko\yii\encryptedattribute\ciphers\AesGcmCipher::class,
        ]);

        $model->secret_decrypted = 'gcm secret';
        $this->assertTrue($model->save());

        $reloaded = Vault::findOne($model->id);
        $reloaded->detachBehavior('encryption');
        $reloaded->attachBehavior('encryption', [
            'class'      => EncryptedAttributeBehavior::class,
            'keyName'    => 'main',
            'attributes' => ['secret'],
            'cipher'     => new \tuzelko\yii\encryptedattribute\ciphers\AesGcmCipher(),
        ]);

        $this->assertSame('gcm secret', $reloaded->secret_decrypted);
    }

    public function testInvalidCipherIsRejectedOnInit(): void
    {
        $model = new Vault();
        $model->detachBehavior('encryption');

        $this->expectException(InvalidConfigException::class);
        $model->attachBehavior('encryption', [
            'class'      => EncryptedAttributeBehavior::class,
            'keyName'    => 'main',
            'attributes' => ['secret'],
            'cipher'     => \stdClass::class,
        ]);
    }

    // -------------------------------------------------------------------------
    // Custom suffix
    // -------------------------------------------------------------------------

    public function testCustomSuffixIsRespected(): void
    {
        $model = new Vault();
        $model->detachBehavior('encryption');
        $model->attachBehavior('encryption', [
            'class'      => EncryptedAttributeBehavior::class,
            'keyName'    => 'main',
            'attributes' => ['secret'],
            'suffix'     => '_plain',
            'cipher'     => \tuzelko\yii\encryptedattribute\ciphers\SodiumSecretboxCipher::class,
        ]);

        $model->secret_plain = 'suffixed';
        $this->assertSame('suffixed', $model->secret_plain);
        $this->assertNotSame('suffixed', $model->secret);
    }
}