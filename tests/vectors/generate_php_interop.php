<?php
require __DIR__ . '/vendor/autoload.php';
use ParagonIE\CipherSweet\{AAD, BlindIndex, CipherSweet, CompoundIndex, EncryptedField, EncryptedRow, EncryptedMultiRows, JsonFieldMap, Constants};
use ParagonIE\CipherSweet\Backend\{BoringCrypto, FIPSCrypto, ModernCrypto};
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\CipherSweet\Transformation\{Lowercase, LastFourDigits, AlphaCharactersOnly, DigitsOnly, FirstCharacter, AlphaNumericCharactersOnly, Compound};

$key = 'b8d2a1a4e9f34c5a7d6e0f1b2c3d4e5f60718293a4b5c6d7e8f9011223344556';
$out = ['key' => $key, 'backends' => []];
foreach (['nacl' => new ModernCrypto(), 'fips' => new FIPSCrypto(), 'brng' => new BoringCrypto()] as $name => $backend) {
    $engine = new CipherSweet(new StringProvider($key), $backend);
    $b = [];

    // EncryptedField with literal AAD + typed/flat indexes (fast + slow)
    $field = (new EncryptedField($engine, 'contacts', 'email'))
        ->addBlindIndex(new BlindIndex('email_lower', [new Lowercase()], 32, true))
        ->addBlindIndex(new BlindIndex('email_first', [new FirstCharacter()], 8, true))
        ->addBlindIndex(new BlindIndex('email_alpha', [new AlphaCharactersOnly()], 300, true))
        ->addBlindIndex(new BlindIndex('email_slow', [new Lowercase()], 64, false));
    $plain = 'Ünïcode.User+Tag/42@Example.COM';
    $b['field'] = [
        'plaintext' => $plain,
        'ct' => $field->encryptValue($plain),
        'ct_aad' => $field->encryptValue($plain, 'row:42'),
        'aad' => 'row:42',
        'indexes' => $field->getAllBlindIndexes($plain),
        'types' => $field->getBlindIndexTypes(),
    ];

    // EncryptedRow with many types and AAD
    $row = (new EncryptedRow($engine, 'users'))
        ->addTextField('name', 'id')
        ->addIntegerField('age')
        ->addFloatField('score')
        ->addBooleanField('active')
        ->addOptionalTextField('nickname')
        ->addOptionalIntegerField('maybe_int')
        ->addOptionalBooleanField('maybe_bool')
        ->addTextField('ssn', new AAD(['id', 'tenant'], ['v1', '10', '9']));
    $row->addBlindIndex('ssn', new BlindIndex('ssn_last4', [new LastFourDigits()], 16, true));
    $row->addBlindIndex('age', new BlindIndex('age_idx', [], 32, true));
    $row->addBlindIndex('active', new BlindIndex('active_idx', [], 8, true));
    $row->addBlindIndex('score', new BlindIndex('score_idx', [], 32, true));
    $cidx = $row->createCompoundIndex('ssn_active', ['ssn', 'active', 'score', 'age', 'name'], 64, true);
    $cidx->addTransform('ssn', new LastFourDigits());
    $row->createCompoundIndex('name_slow', ['name', 'nickname'], 32, false);
    $plainRow = [
        'id' => 42, 'tenant' => 'acme',
        'name' => 'Zoë "Z" O\'Neil / ✓',
        'age' => -7, 'score' => 1.5e-7, 'active' => false,
        'nickname' => null, 'maybe_int' => 12345678901, 'maybe_bool' => null,
        'ssn' => '123-45-6789',
    ];
    $enc = $row->encryptRow($plainRow);
    $b['row'] = [
        'plaintext' => $plainRow,
        'ciphertext' => $enc,
        'indexes' => $row->getAllBlindIndexes($plainRow),
        'compound_type' => $row->getCompoundIndexType('ssn_active'),
        'packed' => $cidx->getPacked($plainRow),
    ];
    $row->setTypedIndexes(true);
    $b['row']['typed_indexes'] = $row->getAllBlindIndexes($plainRow);

    // JSON field
    $map = (new JsonFieldMap())
        ->addTextField(['profile', 'name'])
        ->addIntegerField(['profile', 'age'])
        ->addBooleanField(['flags', 0])
        ->addFloatField('balance');
    $jrow = (new EncryptedRow($engine, 'docs'))->addJsonField('doc', $map, 'id');
    $doc = ['id' => 7, 'doc' => ['profile' => ['name' => 'Ann', 'age' => 30, 'city' => 'Oslo'], 'flags' => [true, false], 'balance' => 10.25]];
    $b['json'] = ['plaintext' => $doc, 'ciphertext' => $jrow->encryptRow($doc), 'map' => $map->toString()];

    // Multi rows, auto-bind context
    $mr = (new EncryptedMultiRows($engine, false, true))
        ->addTextField('orders', 'note')
        ->addIntegerField('items', 'qty');
    $mr->setPrimaryKeyColumnName('orders', 'id');
    $mrows = ['orders' => ['id' => 1, 'note' => 'leave at door'], 'items' => ['qty' => 3]];
    $b['multi'] = ['plaintext' => $mrows, 'ciphertext' => $mr->encryptManyRows($mrows)];

    $b['ext_key'] = bin2hex($engine->getExtensionKey('my-ext', 'a', 'b')->getRawKey());
    $out['backends'][$name] = $b;
}
$floats = [1.0, 0.1, -2.5, 1e15, 1e14, 123456789012345678.0, 0.0001, 0.00001, 1.5e-7, 3.1415, 99.1, 1e100, -0.0];
$out['floats'] = array_map(fn($f) => [$f, (string) $f], $floats);
$out['compound'] = [
    (new Compound())(['a' => 'x/y', 'b' => 1, 'c' => null, 'd' => true, 'e' => 2.5, 'f' => ['n' => 'ü'], 'g' => []]),
];
echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
