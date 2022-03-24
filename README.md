# PHP JWT

Based on [firebase/php-jwt](https://github.com/firebase/phpjwt)

```php
<?php

$options = array(
    'key' => 'mySecr3TKey~',
    // options defaults value
    // 'id' => null, // or jti
    // 'leeway' => 0,
    // 'keyId' => null,
    // 'publicKeys' => array(),
    // 'header' => array(),
    // 'algorithm' => null, // or alg
    // 'issuer' => null, // or iss
    // 'expires' => null, // or exp
    // 'subject' => null, // or sub
    // 'audience' => null, // or aud
    // 'notBefore' => null, // or nbf
    // 'issuedAt' => null, // or iat
);
$jwt = new Ekok\JWT\Manager($options);
$payload = array(
    'foo' => 'bar',
);
$token = $jwt->encode($payload);
$decoded = $jwt->decode($token);

// $decoded === $payload

```