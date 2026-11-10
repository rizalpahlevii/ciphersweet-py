<?php
require __DIR__ . '/vendor/autoload.php';
use ParagonIE\CipherSweet\{AAD, CipherSweet, EncryptedField, EncryptedRow, JsonFieldMap};
use ParagonIE\CipherSweet\Backend\{BoringCrypto, FIPSCrypto, ModernCrypto};
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
$key = 'b8d2a1a4e9f34c5a7d6e0f1b2c3d4e5f60718293a4b5c6d7e8f9011223344556';
$in = json_decode(file_get_contents(__DIR__ . '/py.json'), true);
foreach (['nacl' => new ModernCrypto(), 'fips' => new FIPSCrypto(), 'brng' => new BoringCrypto()] as $n => $b) {
  $e = new CipherSweet(new StringProvider($key), $b);
  $row = (new EncryptedRow($e, 'users'))->addTextField('name','id')->addIntegerField('age')->addFloatField('score')->addBooleanField('active')
    ->addOptionalTextField('nickname')->addTextField('ssn', new AAD(['id','tenant'], ['v1','10','9']));
  $row->addJsonField('doc', (new JsonFieldMap())->addTextField(['p','name'])->addIntegerField(['p','age']), 'id');
  $dec = $row->decryptRow($in[$n]['ct']);
  echo $n, ' row ', json_encode($dec, JSON_UNESCAPED_UNICODE), "\n";
  echo $n, ' field ', (new EncryptedField($e, 'c', 'e'))->decryptValue($in[$n]['field'], 'aad!'), "\n";
  echo $n, ' pw ', bin2hex($b->deriveKeyFromPassword('password', '0123456789abcdef')->getRawKey()) === $in[$n]['pw'] ? 'ok' : 'MISMATCH', "\n";
}
