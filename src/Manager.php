<?php

declare(strict_types=1);

namespace Ekok\JWT;

class Manager
{
    private $options = array();

    public function __construct(array $options = null)
    {
        $this->setOptions($options ?? array());
    }

    public function getOptions(): array
    {
        return $this->options;
    }

    public function setOption(string $option, $value): static
    {
        $this->options[$option] = $value;

        return $this;
    }

    public function setOptions(array $options): static
    {
        $this->options = array();

        array_walk($options, fn($value, $option) => $this->setOption($option, $value));

        return $this;
    }

    public function createToken(string|array $init = null, array $options = null): Token
    {
        return new Token($init, ($options ?? array()) + $this->getOptions());
    }

    public function encode(array $payload = null, array $options = null): string
    {
        return $this->createToken($payload, $options)->getJwt();
    }

    public function decode(string $jwt, array $options = null): array
    {
        return $this->createToken($jwt, $options)->getPayload();
    }
}
