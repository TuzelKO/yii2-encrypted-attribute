<?php

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../vendor/yiisoft/yii2/Yii.php';

new \yii\console\Application([
    'id'         => 'test',
    'basePath'   => __DIR__,
    'components' => [
        'db' => [
            'class' => \yii\db\Connection::class,
            'dsn'   => 'sqlite::memory:',
        ],
    ],
]);

\Yii::$app->db->createCommand(
    'CREATE TABLE vault (
        id     INTEGER PRIMARY KEY AUTOINCREMENT,
        secret TEXT DEFAULT NULL,
        token  TEXT DEFAULT NULL,
        note   TEXT DEFAULT NULL
    )'
)->execute();