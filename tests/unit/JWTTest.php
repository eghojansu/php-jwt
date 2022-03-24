<?php

use Ekok\JWT\Manager;

class JWTTest extends \Codeception\Test\Unit
{
    /** @var Manager */
    private $jwt;

    public function _before()
    {
        $this->jwt = new Manager(array(
            'key' => 'mySecr3TKey~',
        ));
    }

    /** @dataProvider usageProvider */
    public function testUsage(array|string $data, array $options = null)
    {
        list($jwt, $payload) = ((array) $data) + array(
            1 => array(
                'foo' => 'bar',
            ),
        );

        if ($options) {
            $this->jwt->setOptions($options + $this->jwt->getOptions());
        }

        $encoded = $this->jwt->encode($payload);
        $decoded = $this->jwt->decode($encoded);

        $this->assertSame($jwt, $encoded);
        $this->assertSame($decoded, $payload);
    }

    public function usageProvider()
    {
        return array(
            'default HS256' => array(
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.SWFB51rItSA-WE4shY9NMaK0yDCAqNkMsOInNjKG09Q',
            ),
            'HS384' => array(
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJmb28iOiJiYXIifQ.3V8NfyvaTm_zz8cUG1Tcqo5hLWVgdMqyU1IsBj9UV1DiVIOnxUZDmwyX5jHODnlP',
                array(
                    'alg' => 'HS384',
                ),
            ),
            'HS512' => array(
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJmb28iOiJiYXIifQ.4VxMESHhqhuEFxXzvXG9eU2x0gqHst4zYptuQBxMB5Z1EeN8EqMN4NZWyHvlyb4MPoCKCs2SPdIAYtFGLnBgiw',
                array(
                    'alg' => 'HS512',
                ),
            ),
        );
    }

    public function testTokenAccess()
    {
        $token = $this->jwt->createToken(array('foo' => 'bar'));

        $this->assertSame((string) $token, $token->getJwt());
        $this->assertArrayHasKey('notBefore', $token->toArray());
    }

    public function testUsageWithPayload()
    {
        $options = array(
            'nbf' => new DateTime('-1 minute'),
            'iat' => new DateTime('now'),
            'exp' => new DateTime('tomorrow'),
        );
        $payload = array(
            'sub' => 'my_subject',
            'aud' => 'my_audience',
            'iss' => 'my_issuer',
            'jti' => 'my_id',
        );
        $publicKeys = array(
            'foo' => 'bar',
            'bar' => 'baz',
        );

        $this->jwt->setOption('publicKeys', $publicKeys);
        $this->jwt->setOption('key', $publicKeys['bar']);
        $this->jwt->setOption('keyId', 'bar');

        $token = $this->jwt->createToken($payload, $options);
        // $jwt = $this->jwt->encode($payload, $options);
        $jwt = $token->getJwt();
        $pay = $this->jwt->decode($jwt);

        $exp = array_map(static fn($dt) => $dt instanceof DateTime ? $dt->getTimestamp() : $dt, $options);
        $expPublicKeys = array_map(static fn($key) => compact('key') + array('alg' => 'HS256'), $publicKeys);

        $this->assertEquals($payload + $exp, $pay);
        $this->assertEquals($expPublicKeys, $token->getPublicKeys());
    }

    public function testUrlSafeCharacters()
    {
        $jwt = $this->jwt->encode(array('message' => 'f?'));
        $actual = $this->jwt->decode($jwt);
        $expected = array('message' => 'f?');

        $this->assertEquals($expected, $actual);
    }

    /** @dataProvider exceptionsProvider */
    public function testExceptions(string $expected, array $payload, array $options = null, string $exception = null)
    {
        $this->expectException($exception ?? 'RuntimeException');
        $this->expectExceptionMessageMatches($expected);

        $this->jwt->decode(
            $this->jwt->encode($payload, $options),
            $options,
        );
    }

    public function exceptionsProvider()
    {
        return array(
            'expired token' => array(
                '/^Expired token$/',
                array(
                    'message' => 'abc',
                    'exp' => time() - 20, // time in past
                ),
            ),
            'expired token with leeway' => array(
                '/^Expired token$/',
                array(
                    'message' => 'abc',
                    'exp' => time() - 70, // time far in the past
                ),
                array(
                    'leeway' => 60,
                ),
            ),
            'invalid token with nbf leeway' => array(
                '/^Cannot handle token prior to/',
                array(
                    'message' => 'abc',
                    'nbf' => time() + 65, // not before too far in future
                ),
                array(
                    'leeway' => 60,
                ),
            ),
            'invalid token with iat leeway' => array(
                '/^Cannot handle token prior to/',
                array(
                    'message' => 'abc',
                    'iat' => time() + 65, // issued too far in future
                ),
                array(
                    'leeway' => 60,
                ),
            ),
            'before valid token (nbf)' => array(
                '/^Cannot handle token prior to/',
                array(
                    'message' => 'abc',
                    'nbf' => time() + 20, // time in future
                ),
            ),
            'before valid token (iat)' => array(
                '/^Cannot handle token prior to/',
                array(
                    'message' => 'abc',
                    'iat' => time() + 20, // time in future
                ),
            ),
            'invalid token' => array(
                '/^Signature verification failed$/',
                array(
                    'message' => 'abc',
                ),
                array(
                    'publicKeys' => array('foo'),
                ),
            ),
            'hmac null key' => array(
                '/^Key must be a string when using hmac$/',
                array(
                    'message' => 'abc',
                ),
                array(
                    'key' => null,
                ),
                'InvalidArgumentException',
            ),
            'edsa null key' => array(
                '/^Key must be a string when using EdDSA$/',
                array(
                    'message' => 'abc',
                ),
                array(
                    'key' => null,
                    'alg' => 'EdDSA',
                ),
                'InvalidArgumentException',
            ),
            'invalid algorithm' => array(
                '/^Algorithm not supported$/',
                array(
                    'message' => 'abc',
                ),
                array(
                    'alg' => '',
                ),
                'DomainException',
            ),
            'invalid option' => array(
                '/^Invalid option: foo$/',
                array(
                    'message' => 'abc',
                ),
                array(
                    'foo' => '',
                ),
                'DomainException',
            ),
            'Malformed Utf8 Strings Fail' => array(
                '/^Malformed UTF-8 characters, possibly incorrectly encoded$/',
                array(
                    'message' => pack('c', 128),
                ),
                null,
                'JsonException',
            ),
        );
    }

    /** @dataProvider decodeExceptionProvider */
    public function testDecodeException(string $expected, string $jwt, array $options = null, string $exception = null)
    {
        $this->expectException($exception ?? 'RuntimeException');
        $this->expectExceptionMessageMatches($expected);

        $this->jwt->decode($jwt, $options);
    }

    public function decodeExceptionProvider()
    {
        return array(
            'invalid segments' => array(
                '/^Wrong number of segments$/',
                'foo',
            ),
            'empty algorithm' => array(
                '/^Empty algorithm$/',
                'W10.eyJmb28iOiJiYXIifQ.SWFB51rItSA-WE4shY9NMaK0yDCAqNkMsOInNjKG09Q',
            ),
            'none algorithm' => array(
                '/^Algorithm not supported$/',
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ.SWFB51rItSA-WE4shY9NMaK0yDCAqNkMsOInNjKG09Q',
                array(
                    'alg' => 'none',
                ),
                'DomainException',
            ),
            'incorect algorithm' => array(
                '/^Incorrect key for this algorithm$/',
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.SWFB51rItSA-WE4shY9NMaK0yDCAqNkMsOInNjKG09Q',
                array(
                    'publicKeys' => array(
                        array( // default public keys
                            'anything',
                            '_alg' => 'HS384',
                        ),
                    ),
                ),
                'UnexpectedValueException',
            ),
            'edsa null key' => array(
                '/^Key must be a string when using EdDSA$/',
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJmb28iOiJiYXIifQ.OyObjBTJFi3tWL4nxlyOlCfW2ACHs6bBovJ15aGZ_mSH6bdsSZB3lAapgj5ol5Jw9qwWkFGl5gpAOdUhDqaqBA',
                array(
                    'key' => null,
                    'alg' => 'EdDSA',
                ),
                'InvalidArgumentException',
            ),
        );
    }

    public function testDERUsage()
    {
        $privKey = openssl_pkey_new(array(
            'digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ));
        $pubKey = openssl_pkey_get_details($privKey);
        $pubKey = $pubKey['key'];

        $this->jwt->setOption('alg', 'RS256');
        $this->jwt->setOption('key', $privKey);
        $this->jwt->setOption('publicKeys', array($pubKey));

        $msg = $this->jwt->encode(array('message' => 'abc'));
        $decoded = $this->jwt->decode($msg);
        $expected = array('message' => 'abc');

        $this->assertEquals($decoded, $expected);
    }
}
