<?php

namespace TheNetworg\OAuth2\Client\Tests\Fakers;


class B2cKeysFaker
{
    /**
     * @param $publicKey
     * @param $modulus
     * @param $exponent
     * @return array<string, mixed>
     */
    public function getB2cKeysResponse($publicKey, $modulus, $exponent): array
    {

        return array(
            'keys' => [
                array(
                    'kid' => $publicKey,
                    'nbf' => time(),
                    'use' => 'sig',
                    'kty' => 'RSA',
                    'e' => $exponent,
                    'n' => $modulus
                )
            ]
        );
    }


}
