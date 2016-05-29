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
        // if (empty($options['access_token'])) {
        //     throw new InvalidArgumentException('Required option not passed: "access_token"');
        // }

        if(isset($options['access_token'])) $this->accessToken = $options['access_token'];

        if (!empty($options['resource_owner_id'])) {
            $this->resourceOwnerId = $options['resource_owner_id'];
        }

        if (!empty($options['refresh_token'])) {
            $this->refreshToken = $options['refresh_token'];
        }

        // We need to know when the token expires. Show preference to
        // 'expires_in' since it is defined in RFC6749 Section 5.1.
        // Defer to 'expires' if it is provided instead.
        if (!empty($options['expires_in'])) {
            $this->expires = time() + ((int) $options['expires_in']);
        } elseif (!empty($options['expires'])) {
            // Some providers supply the seconds until expiration rather than
            // the exact timestamp. Take a best guess at which we received.
            $expires = $options['expires'];

            if (!$this->isExpirationTimestamp($expires)) {
                $expires += time();
            }

            $this->expires = $expires;
        }

        // Capure any additional values that might exist in the token but are
        // not part of the standard response. Vendors will sometimes pass
        // additional user data this way.
        $this->values = array_diff_key($options, array_flip([
            'access_token',
            'resource_owner_id',
            'refresh_token',
            'expires_in',
            'expires',
        ]));
        
        if (!empty($options['id_token'])) {
            $this->idToken = $options['id_token'];
            
            if(!isset($options['access_token'])) $options['access_token'] = null;
            
            $this->idTokenClaims = $provider->validateToken($options['access_token'], $options['id_token']);
        }
    }
    
    public function getIdTokenClaims()
    {
        return $this->idTokenClaims;
    }
}