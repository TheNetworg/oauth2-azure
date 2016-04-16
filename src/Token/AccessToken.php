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
            
            $jwt = $this->accessToken;
            $keys = $this->getJwtVerificationKeys($provider);
            
            try {
                $idTokenClaims = (array)JWT::decode($jwt, $keys, ['RS256']);
            }  catch (JWT_Exception $e) {
                throw new RuntimeException("Unable to parse the id_token!");
            }
            
            print_r($idTokenClaims);
            
            if($provider->getClientId() != $idTokenClaims['appid']) {
                throw new RuntimeException("The token wasn't meant for this applicaiton!");
            }
            if($idTokenClaims['nbf'] > time() || $idTokenClaims['exp'] < time()) {
                throw new RuntimeException("The id_token is invalid!");
            }
            
            if($provider->tenant == "common") {
                $provider->tenant = $idTokenClaims['tid'];
                
                $tenant = $this->getTenantDetails($provider->tenant, $provider);
                if($idTokenClaims['iss'] != $tenant['issuer']) {
                    throw new RuntimeException("Invalid token issuer!");
                }
            }
            else {
                $tenant = $this->getTenantDetails($provider->tenant, $provider);
                if($idTokenClaims['iss'] != $tenant['issuer']) {
                    throw new RuntimeException("Invalid token issuer!");
                }
            }
            
            $this->idTokenClaims = $idTokenClaims;
        }
    }
    
    /**
     * Get JWT verification keys from Azure Active Directory.
     *
     * @return array
     */
    private function getJwtVerificationKeys($provider)
    {
        $factory = $provider->getRequestFactory();
        $request = $factory->getRequestWithOptions('get', 'https://login.windows.net/common/discovery/keys', []);
        
        $response = $provider->getResponse($request);
        
        $keys = [];
        foreach ($response['keys'] as $i => $keyinfo) {
            if (isset($keyinfo['x5c']) && is_array($keyinfo['x5c'])) {
                foreach ($keyinfo['x5c'] as $encodedkey) {
                    $key = "-----BEGIN CERTIFICATE-----\n";
                    $key .= wordwrap($encodedkey, 64, "\n", true);
                    $key .= "\n-----END CERTIFICATE-----";
                    $keys[$keyinfo['kid']] = $key;
                }
            }
        }
        
        return $keys;
    }
    
    /**
     * Get the specified tenant's details.
     *
     * @param string $tenant
     *
     * @return array
     */
    private function getTenantDetails($tenant, $provider)
    {
        $factory = $provider->getRequestFactory();
        $request = $factory->getRequestWithOptions('get', 'https://login.windows.net/'.$tenant.'/.well-known/openid-configuration', []);
        
        $response = $provider->getResponse($request);
        
        return $response;
    }
    
    public function getIdTokenClaims()
    {
        return $this->idTokenClaims;
    }
}