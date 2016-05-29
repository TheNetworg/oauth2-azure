<?php

namespace TheNetworg\OAuth2\Client\Token;

use InvalidArgumentException;
use RuntimeException;
use League\OAuth2\Client\Tool\RequestFactory;
use \Firebase\JWT\JWT;

class AccessToken extends \League\OAuth2\Client\Token\AccessToken
{
    protected $idToken;
    protected $idTokenClaims;
    
    public function __construct(array $options = [], $provider)
    {
        parent::__construct($options);
        if (!empty($options['id_token'])) {
            $this->idToken = $options['id_token'];
            
            $this->idTokenClaims = $provider->validateToken($options['access_token'], $options['id_token']);
        }
    }
    
    public function getIdTokenClaims()
    {
        return $this->idTokenClaims;
    }
}