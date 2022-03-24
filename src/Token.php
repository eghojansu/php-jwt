<?php

declare(strict_types=1);

namespace Ekok\JWT;

class Token
{
    private const OPTIONS_MAPS = array(
        'alg' => 'algorithm',
        'kid' => 'keyId',
    );
    private const PAYLOAD_MAPS = array(
        'iss' => 'issuer',
        'sub' => 'subject',
        'aud' => 'audience',
        'exp' => 'expires',
        'nbf' => 'notBefore',
        'iat' => 'issuedAt',
        'jti' => 'id',
    );

    private $id;
    private $leeway = 0;
    private $keyId;
    private $key;
    private $publicKeys = array();
    private $header = array();
    private $algorithm;
    private $issuer;
    private $expires;
    private $subject;
    private $audience;
    private $notBefore;
    private $issuedAt;
    private $init;
    private $jwt;
    private $payload;

    public function __construct(
        string|array $init = null,
        array $options = null,
    ) {
        $this->init = $init;
        $this->apply($options ?? array());
    }

    public function __toString()
    {
        return $this->getJwt();
    }

    public function getPayload(): array
    {
        return $this->payload ?? $this->doProcess()->payload;
    }

    public function getJwt(): string
    {
        return $this->jwt ?? $this->doProcess()->jwt;
    }

    public function apply(array $options, bool $safe = false): static
    {
        array_walk($options, function($value, $option) use ($safe) {
            $set = 'set' . (self::PAYLOAD_MAPS[$option] ?? self::OPTIONS_MAPS[$option] ?? $option);

            if (method_exists($this, $set)) {
                $this->$set($value);
            } elseif (!$safe) {
                throw new \DomainException(sprintf('Invalid option: %s', $option));
            }
        });

        return $this;
    }

    public function toArray(): array
    {
        return array(
            'id' => $this->getId(),
            'leeway' => $this->getLeeway(),
            'key' => $this->getKey(),
            'keyId' => $this->getKeyId(),
            'publicKeys' => $this->getPublicKeys(),
            'header' => $this->getHeader(),
            'algorithm' => $this->getAlgorithm(),
            'issuer' => $this->getIssuer(),
            'expires' => $this->getExpires(),
            'subject' => $this->getSubject(),
            'audience' => $this->getAudience(),
            'notBefore' => $this->getNotBefore(),
            'issuedAt' => $this->getIssuedAt(),
        );
    }

    public function toPayload(): array
    {
        return array_reduce(
            self::PAYLOAD_MAPS,
            fn(array $payload, $name) => $payload + array(
                array_search($name, self::PAYLOAD_MAPS) => $this->{'get' . $name}(),
            ),
            array(),
        );
    }

    public function getId(): string|null
    {
        return $this->id;
    }

    public function setId(string|null $id): static
    {
        $this->id = $id;

        return $this;
    }

    public function getLeeway(): int
    {
        return $this->leeway;
    }

    public function setLeeway(int $leeway): static
    {
        $this->leeway = $leeway;

        return $this;
    }

    public function getKey(): \OpenSSLAsymmetricKey|\OpenSSLCertificate|array|string|null
    {
        return $this->key;
    }

    public function setKey(\OpenSSLAsymmetricKey|\OpenSSLCertificate|array|string|null $key): static
    {
        $this->key = $key;

        return $this;
    }

    public function getPublicKey(string &$alg = null, string $id = null): \OpenSSLAsymmetricKey|\OpenSSLCertificate|array|string|null
    {
        list('alg' => $alg, 'key' => $key) = $this->publicKeys[$id ?? $this->getKeyId() ?? 'default'] ?? array(
            'alg' => null,
            'key' => null,
        );

        return $key;
    }

    public function addPublicKey(
        \OpenSSLAsymmetricKey|\OpenSSLCertificate|array|string|null $key,
        string $id = null,
        string $algorithm = null,
    ): static {
        $alg = $algorithm ?? $this->getAlgorithm();

        if (is_array($key) && isset($key['_alg'])) {
            $alg = $key['_alg'];
            $key = $key['key'] ?? $key[0] ?? null;
        }

        $this->publicKeys[$id ?? 'default'] = compact('alg', 'key');

        return $this;
    }

    public function getPublicKeys(): array
    {
        return $this->publicKeys;
    }

    public function setPublicKeys(array $keys): static
    {
        $this->publicKeys = array();

        if ($keys) {
            array_walk($keys, function($key, $id) {
                $this->addPublicKey($key, is_string($id) ? $id : null);
            });
        }

        return $this;
    }

    public function getKeyId(): string|null
    {
        return $this->keyId;
    }

    public function setKeyId(string|null $key): static
    {
        $this->keyId = $key;

        return $this;
    }

    public function getHeader(): array
    {
        return $this->header ?? array();
    }

    public function setHeader(array|null $header): static
    {
        $this->header = $header;

        return $this;
    }

    public function getAlgorithm(): string
    {
        return $this->algorithm ?? 'HS256';
    }

    public function setAlgorithm(string $algorithm): static
    {
        $this->algorithm = $algorithm;

        return $this;
    }

    public function getIssuer(): string|null
    {
        return $this->issuer;
    }

    public function setIssuer(string|null $issuer): static
    {
        $this->issuer = $issuer;

        return $this;
    }

    public function getExpires(): int|null
    {
        return match(true) {
            $this->expires instanceof \DateTime => $this->expires->getTimestamp(),
            default => $this->expires,
        };
    }

    public function setExpires(\DateTime|int|null $expires): static
    {
        $this->expires = $expires;

        return $this;
    }

    public function getSubject(): string|null
    {
        return $this->subject;
    }

    public function setSubject(string|null $subject): static
    {
        $this->subject = $subject;

        return $this;
    }

    public function getAudience(): string|null
    {
        return $this->audience;
    }

    public function setAudience(string|null $audience): static
    {
        $this->audience = $audience;

        return $this;
    }

    public function getNotBefore(): int|null
    {
        return match(true) {
            $this->notBefore instanceof \DateTime => $this->notBefore->getTimestamp(),
            default => $this->notBefore,
        };
    }

    public function setNotBefore(\DateTime|int|null $notBefore): static
    {
        $this->notBefore = $notBefore;

        return $this;
    }

    public function getIssuedAt(): int|null
    {
        return match(true) {
            $this->issuedAt instanceof \DateTime => $this->issuedAt->getTimestamp(),
            default => $this->issuedAt,
        };
    }

    public function setIssuedAt(\DateTime|int|null $issuedAt): static
    {
        $this->issuedAt = $issuedAt;

        return $this;
    }

    private function doProcess(): static
    {
        $payload = $this->init ?? array();

        if (is_string($payload)) {
            $jwt = $payload;
            $payload = $this->doDecode($jwt, $updates);
        } else {
            $jwt = $this->doEncode($payload, $updates);
        }

        $this->jwt = $jwt;
        $this->payload = $payload;

        return $this->apply($updates, true);
    }

    private function doEncode(array $payload, array &$updates = null): string
    {
        $jwt = $this->encodeHeader($header);
        $jwt .= '.' . $this->encodePayload($payload);
        $jwt .= '.' . Utils::sign($jwt, $this->getAlgorithm(), $this->getKey());

        $updates = compact('header');

        return $jwt;
    }

    private function doDecode(string $jwt, array &$updates = null): array
    {
        $start = time();
        $parts = explode('.', $jwt);

        if (!isset($parts[2]) || isset($parts[3])) {
            throw new \UnexpectedValueException('Wrong number of segments');
        }

        list($rawHeader, $rawBody, $rawSignature) = $parts;

        $header = $this->decodeHeader($rawHeader);

        if (empty($header['alg'])) {
            throw new \UnexpectedValueException('Empty algorithm');
        }

        $key = (
            $this->getPublicKey($alg, $header['kid'] ?? null) ??
            $this->getKey($alg = $this->getAlgorithm())
        );

        // Check the algorithm
        if (!hash_equals($alg, $header['alg'])) {
            throw new \UnexpectedValueException('Incorrect key for this algorithm');
        }

        Utils::verify("$rawHeader.$rawBody", $alg, $rawSignature, $key);

        $payload = $this->decodePayload($parts[1]);
        $leeway = $this->getLeeway();

        // Check the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        if (($payload['nbf'] ?? 0) > ($start + $leeway)) {
            throw new \RuntimeException(sprintf(
                'Cannot handle token prior to %s',
                date(\DateTime::ISO8601, $payload['nbf'])
            ));
        }

        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if (($payload['iat'] ?? 0) > ($start + $leeway)) {
            throw new \RuntimeException(sprintf(
                'Cannot handle token prior to %s',
                date(\DateTime::ISO8601, $payload['iat'])
            ));
        }

        // Check if this token has expired.
        if (isset($payload['exp']) && ($start - $leeway) >= $payload['exp']) {
            throw new \RuntimeException('Expired token');
        }

        $updates = compact('header') + array_intersect_key($payload, self::PAYLOAD_MAPS);

        return $payload;
    }

    private function encodeHeader(array &$header = null): string
    {
        $header = array(
            'typ' => 'JWT',
            'alg' => $this->getAlgorithm(),
        ) + $this->getHeader();

        if ($kid = $this->getKeyId()) {
            $header['kid'] = $kid;
        }

        return Utils::jsonEncode($header);
    }

    private function encodePayload(array $data): string
    {
        $payload = $data + array_filter($this->toPayload(), 'is_scalar');

        return Utils::jsonEncode($payload);
    }

    private function decodeHeader(string $raw): array
    {
        return Utils::jsonDecode($raw);
    }

    private function decodePayload(string $raw): array
    {
        return Utils::jsonDecode($raw);
    }
}
