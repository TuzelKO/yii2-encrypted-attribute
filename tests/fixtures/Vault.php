<?php

namespace tuzelko\yii\encryptedattribute\tests\fixtures;

use tuzelko\yii\encryptedattribute\ciphers\SodiumSecretboxCipher;
use tuzelko\yii\encryptedattribute\EncryptedAttributeBehavior;
use yii\db\ActiveRecord;

/**
 * @property int $id
 * @property string|null $secret
 * @property string|null $token
 * @property string|null $note
 *
 * @property string|null $secret_decrypted
 * @property string|null $token_decrypted
 */
class Vault extends ActiveRecord
{
    public static function tableName(): string
    {
        return 'vault';
    }

    public function behaviors(): array
    {
        return [
            'encryption' => [
                'class'      => EncryptedAttributeBehavior::class,
                'keyName'    => 'main',
                'attributes' => ['secret', 'token'],
                'cipher'     => SodiumSecretboxCipher::class,
            ],
        ];
    }
}