<?php
require 'Crypto.php';

$bob_public = '049fdbf6d4ca6109867d2d0d26f327ceb8cc433024499d712abf9d7207708765ad626a7ea05f3b9bb50e1bf53a9a6ef92c2ae1a68d85f674867a01bf4007fdd3ab';

$c = new Crypto();
// Alice
$alice_private_key = $c->makeKey(32);
echo "Alice Private: $alice_private_key\n";
$alice_public_key = $c->derivePublic($alice_private_key);
echo "Alice Public: $alice_public_key\n";
echo "\n";
// Bob
$bob_private_key = $c->makeKey(32);
echo "Bob Private: $bob_private_key\n";
$bob_public_key = $c->derivePublic($bob_private_key);
echo "Bob Public: $bob_public_key\n";
echo "\n";
// Public keys are exchanged
$alice_secret = $c->deriveSharedSecret($alice_private_key, $bob_public_key);
echo "Alice Secret: $alice_secret\n";
$bob_secret = $c->deriveSharedSecret($bob_private_key, $alice_public_key);
echo "Bob Secret: $bob_secret\n";
// Secure communication can now take place
$iv = $c->makeIv();
$encrypted = $c->encrypt("Hello World, This is much longer though", $alice_secret, $iv);
$enc_hex = bin2hex($encrypted);
echo "\nEncrypted: $enc_hex\n";
$decrypted = $c->decrypt($encrypted, $bob_secret, $iv);
echo "\nDecrypted: $decrypted\n";
