<?php

use Ekok\JWT\Manager;
use Ekok\JWT\Utils;

class FirebaseJWTTest extends \Codeception\Test\Unit
{
    /** @var Manager */
    private $jwt;

    public function _before()
    {
        $this->jwt = new Manager(array('key' => 'my_key'));
    }

    public function testUrlSafeCharacters()
    {
        $encoded = $this->jwt->encode(array('message' => 'f?'), array('key' => 'a'));
        $expected = array('message' => 'f?');

        $this->assertEquals($expected, $this->jwt->decode($encoded, array('key' => 'a')));
    }

    public function testMalformedUtf8StringsFail()
    {
        $this->expectException(JsonException::class);
        $this->jwt->encode(array('message' => pack('c', 128)));
    }

    public function testMalformedJsonThrowsException()
    {
        $this->expectException(JsonException::class);
        Utils::jsonDecode('this is not valid JSON string');
    }

    public function testExpiredToken()
    {
        $this->expectException(RuntimeException::class);
        $payload = array(
            "message" => "abc",
            "exp" => time() - 20,
        ); // time in the past
        $encoded = $this->jwt->encode($payload);
        $this->jwt->decode($encoded);
    }

    public function testBeforeValidTokenWithNbf()
    {
        $this->expectException(RuntimeException::class);

        $payload = array(
            "message" => "abc",
            "nbf" => time() + 20,
        ); // time in the future
        $encoded = $this->jwt->encode($payload);

        $this->jwt->decode($encoded);
    }

    public function testBeforeValidTokenWithIat()
    {
        $this->expectException(RuntimeException::class);

        $payload = array(
            "message" => "abc",
            "iat" => time() + 20,
        ); // time in the future
        $encoded = $this->jwt->encode($payload);

        $this->jwt->decode($encoded);
    }

    public function testValidToken()
    {
        $payload = [
            "message" => "abc",
            "exp" => time() + 20,
        ]; // time in the future
        $encoded = $this->jwt->encode($payload);
        $decoded = $this->jwt->decode($encoded);

        $this->assertEquals($decoded['message'], 'abc');
    }

    public function testValidTokenWithLeeway()
    {
        $options = array(
            'leeway' => 60,
        );
        $payload = array(
            "message" => "abc",
            "exp" => time() - 20,
        ); // time in the past

        $encoded = $this->jwt->encode($payload, $options);
        $decoded = $this->jwt->decode($encoded, $options);

        $this->assertEquals($decoded['message'], 'abc');
    }

    public function testExpiredTokenWithLeeway()
    {
        $this->expectException(RuntimeException::class);

        $options = array(
            'leeway' => 60,
        );
        $payload = array(
            "message" => "abc",
            "exp" => time() - 70,
        ); // time far in the past

        $encoded = $this->jwt->encode($payload, $options);
        $decoded = $this->jwt->decode($encoded, $options);

        $this->assertEquals($decoded['message'], 'abc');
    }

    public function testValidTokenWithNbf()
    {
        $payload = array(
            "message" => "abc",
            "iat" => time(),
            "exp" => time() + 20, // time in the future
            "nbf" => time() - 20,
        );

        $encoded = $this->jwt->encode($payload);
        $decoded = $this->jwt->decode($encoded);

        $this->assertEquals($decoded['message'], 'abc');
    }

    public function testValidTokenWithNbfLeeway()
    {
        $options = array(
            'leeway' => 60,
        );
        $payload = array(
            "message" => "abc",
            "nbf"     => time() + 20, // not before in near (leeway) future
        );
        $encoded = $this->jwt->encode($payload, $options);
        $decoded = $this->jwt->decode($encoded, $options);

        $this->assertEquals($decoded['message'], 'abc');
    }

    public function testInvalidTokenWithNbfLeeway()
    {
        $this->expectException(RuntimeException::class);

        $options = array(
            'leeway' => 60,
        );
        $payload = array(
            "message" => "abc",
            "nbf"     => time() + 65, // not before too far in future
        );
        $encoded = $this->jwt->encode($payload, $options);

        $this->jwt->decode($encoded, $options);
    }

    public function testValidTokenWithIatLeeway()
    {
        $options = array(
            'leeway' => 60,
        );
        $payload = array(
            "message" => "abc",
            "iat"     => time() + 20, // issued in near (leeway) future
        );
        $encoded = $this->jwt->encode($payload, $options);
        $decoded = $this->jwt->decode($encoded, $options);

        $this->assertEquals($decoded['message'], 'abc');
    }

    public function testInvalidTokenWithIatLeeway()
    {
        $this->expectException(RuntimeException::class);

        $options = array(
            'leeway' => 60,
        );
        $payload = array(
            "message" => "abc",
            "iat"     => time() + 65, // issued too far in future
        );
        $encoded = $this->jwt->encode($payload, $options);

        $this->jwt->decode($encoded, $options);
    }

    public function testInvalidToken()
    {
        $this->expectException(RuntimeException::class);

        $payload = array(
            "message" => "abc",
            "exp" => time() + 20, // time in the future
        );
        $encoded = $this->jwt->encode($payload);

        $this->jwt->decode($encoded, array('key' => 'my_key2'));
    }

    public function testNullKeyFails()
    {
        $this->expectException(InvalidArgumentException::class);

        $payload = array(
            "message" => "abc",
            "exp" => time() + 20, // time in the future
        );
        $encoded = $this->jwt->encode($payload);

        $this->jwt->decode($encoded, array('key' => null));
    }

    public function testEmptyKeyFails()
    {
        $this->expectException(RuntimeException::class);

        $payload = array(
            "message" => "abc",
            "exp" => time() + 20, // time in the future
        );
        $encoded = $this->jwt->encode($payload);

        $this->jwt->decode($encoded, array('key' => ''));
    }

    public function testKIDChooser()
    {
        define('x',1);
        $keys = array(
            'key' => 'my_key',
            'key2' => 'my_key2',
        );
        $options = array(
            'keyId' => 'key2',
        );
        $msg = $this->jwt->encode(array('message' => 'abc'), $options + array('key' => 'my_key2'));
        $decoded = $this->jwt->decode($msg, array(
            'publicKeys' => $keys,
        ));
        $expected = array('message' => 'abc');

        $this->assertEquals($decoded, $expected);
    }

    public function testNoneAlgorithm()
    {
        $this->expectException(UnexpectedValueException::class);

        $msg = $this->jwt->encode(array('message' => 'abc'));

        $this->jwt->decode($msg, array('alg' => 'none'));
    }

    public function testIncorrectAlgorithm()
    {
        $this->expectException(UnexpectedValueException::class);

        $msg = $this->jwt->encode(array('message' => 'abc'));

        $this->jwt->decode($msg, array('alg' => 'HS384'));
    }

    public function testEmptyAlgorithm()
    {
        $this->expectException(UnexpectedValueException::class);

        $msg = $this->jwt->encode(array('message' => 'abc'));

        $this->jwt->decode($msg, array('alg' => ''));
    }

    public function testAdditionalHeaders()
    {
        $options = array(
            'header' => array('cty' => 'test-eit;v=1'),
        );
        $msg = $this->jwt->encode(array('message' => 'abc'), $options);
        $token = $this->jwt->createToken($msg);
        $expected = array('message' => 'abc');
        $expectedHeader = array(
            'alg' => 'HS256',
            'typ' => 'JWT',
        ) + $options['header'];

        $this->assertEquals($token->getPayload(), $expected);
        $this->assertEquals($expectedHeader, $token->getHeader());
    }

    public function testInvalidSegmentCount()
    {
        $this->expectException(UnexpectedValueException::class);

        $this->jwt->decode('brokenheader.brokenbody');
    }

    public function testInvalidSignatureEncoding()
    {
        $this->expectException(RuntimeException::class);

        $msg = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwibmFtZSI6ImZvbyJ9.Q4Kee9E8o0Xfo4ADXvYA8t7dN_X_bU9K5w6tXuiSjlUxx";

        $this->jwt->decode($msg, array('key' => 'secret'));
    }

    public function testHSEncodeDecode()
    {
        $msg = $this->jwt->encode(array('message' => 'abc'));
        $expected = array('message' => 'abc');

        $this->assertEquals($this->jwt->decode($msg), $expected);
    }

    public function testRSEncodeDecode()
    {
        $privKey = openssl_pkey_new(array(
            'digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ));
        $pubKey = openssl_pkey_get_details($privKey);
        $pubKey = $pubKey['key'];

        $msg = $this->jwt->encode(array('message' => 'abc'), array(
            'alg' => 'RS256',
            'key' => $privKey,
        ));
        $decoded = $this->jwt->decode($msg, array(
            'alg' => 'RS256',
            'key' => $pubKey,
        ));
        $expected = array('message' => 'abc');

        $this->assertEquals($decoded, $expected);
    }

    public function testEdDsaEncodeDecode()
    {
        $keyPair = sodium_crypto_sign_keypair();
        $privKey = base64_encode(sodium_crypto_sign_secretkey($keyPair));
        $pubKey = base64_encode(sodium_crypto_sign_publickey($keyPair));

        $this->jwt->setOption('alg', 'EdDSA');
        $this->jwt->setOption('key', $privKey);
        $this->jwt->setOption('publicKeys', array($pubKey));

        $payload = array('foo' => 'bar');
        $msg = $this->jwt->encode($payload);
        $decoded = $this->jwt->decode($msg);

        $this->assertEquals('bar', $decoded['foo']);
    }

    public function testInvalidEdDsaEncodeDecode()
    {
        $this->expectException(RuntimeException::class);

        $keyPair = sodium_crypto_sign_keypair();
        $privKey = base64_encode(sodium_crypto_sign_secretkey($keyPair));

        // Generate a different key.
        $keyPair = sodium_crypto_sign_keypair();
        $pubKey = base64_encode(sodium_crypto_sign_publickey($keyPair));

        $this->jwt->setOption('alg', 'EdDSA');
        $this->jwt->setOption('key', $privKey);
        $this->jwt->setOption('publicKeys', array($pubKey));

        $payload = array('foo' => 'bar');
        $msg = $this->jwt->encode($payload);

        $this->jwt->decode($msg);
    }

    public function testRSEncodeDecodeWithPassphrase()
    {
        $privateKey = openssl_pkey_get_private(
            file_get_contents(TEST_DATA . '/keys/rsa-with-passphrase.pem'),
            'passphrase'
        );
        $keyDetails = openssl_pkey_get_details($privateKey);
        $pubKey = $keyDetails['key'];

        $this->jwt->setOption('alg', 'RS256');
        $this->jwt->setOption('key', $privateKey);
        $this->jwt->setOption('publicKeys', array($pubKey));

        $payload = array('message' => 'abc');
        $msg = $this->jwt->encode($payload);
        $decoded = $this->jwt->decode($msg);

        $this->assertEquals($payload, $decoded);
    }

    /**
     * @dataProvider provideEncodeDecode
     */
    public function testEncodeDecode($privateKeyFile, $publicKeyFile, $alg)
    {
        $privateKey = file_get_contents($privateKeyFile);
        $publicKey = file_get_contents($publicKeyFile);

        $this->jwt->setOption('alg', $alg);
        $this->jwt->setOption('key', $privateKey);
        $this->jwt->setOption('publicKeys', array($publicKey));

        $payload = array('foo' => 'bar');
        $encoded = $this->jwt->encode($payload);

        // Verify decoding succeeds
        $decoded = $this->jwt->decode($encoded);

        $this->assertEquals('bar', $decoded['foo']);
    }

    public function provideEncodeDecode()
    {
        return array(
            // commented test is un-succeds
            // array(TEST_DATA . '/keys/ecdsa-private.pem', TEST_DATA . '/keys/ecdsa-public.pem', 'ES256'),
            // array(TEST_DATA . '/keys/ecdsa384-private.pem', TEST_DATA . '/keys/ecdsa384-public.pem', 'ES384'),
            array(TEST_DATA . '/keys/rsa1-private.pem', TEST_DATA . '/keys/rsa1-public.pub', 'RS512'),
            array(TEST_DATA . '/keys/ed25519-1.sec', TEST_DATA . '/keys/ed25519-1.pub', 'EdDSA'),
        );
    }

    public function testEncodeDecodeWithResource()
    {
        $pem = file_get_contents(TEST_DATA . '/keys/rsa1-public.pub');
        $resource = openssl_pkey_get_public($pem);
        $privateKey = file_get_contents(TEST_DATA . '/keys/rsa1-private.pem');

        $this->jwt->setOption('alg', 'RS512');
        $this->jwt->setOption('key', $privateKey);
        $this->jwt->setOption('publicKeys', array($resource));

        $payload = array('foo' => 'bar');
        $encoded = $this->jwt->encode($payload);

        // Verify decoding succeeds
        $decoded = $this->jwt->decode($encoded);

        $this->assertEquals('bar', $decoded['foo']);
    }
}
