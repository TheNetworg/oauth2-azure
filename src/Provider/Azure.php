<?php

namespace TheNetworg\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use League\OAuth2\Client\Grant\AbstractGrant;
use TheNetworg\OAuth2\Client\Grant\JwtBearer;
use TheNetworg\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;
use \Firebase\JWT\JWT;

class Azure extends AbstractProvider
{
    use BearerAuthorizationTrait;

    public $metadata = "https://login.microsoftonline.com/common/.well-known/openid-configuration";
    
    public $scope = [];

    public $resource = null;
    
    private $openIdConfiguration = [
        'default' => null,
        'signup' => null,
        'signin' => null,
        'userprofile' => null
    ];
    
    public $policies = [
        'signup' => null,
        'signin' => null,
        'userprofile' => null
    ];

    public function __construct(array $options = [], array $collaborators = [])
    {
        if(isset($options['metadata'])) {
            $this->metadata = $options['metadata'];
        }
        
        parent::__construct($options, $collaborators);
        $this->grantFactory->setGrant('jwt_bearer', new JwtBearer);
        $this->openIdConfiguration['default'] = $this->getOpenIdConfiguration($this->metadata);
    }

    public function getBaseAuthorizationUrl($policy = 'default')
    {
        return $this->openIdConfiguration[$policy]['authorization_endpoint'];
    }

    public function getBaseAccessTokenUrl(array $params)
    {
        $policy = isset($params['policy']) ? $params['policy'] : 'default';
        return $this->openIdConfiguration[$policy]['token_endpoint'];
    }
    
    public function getAccessToken($grant, array $options = [])
    {
        if($this->resource != null) {
            $options['resource'] = $this->resource;
        }
        return parent::getAccessToken($grant, $options);
    }

    protected function checkResponse(ResponseInterface $response, $data)
    {
        if (isset($data['odata.error']) || isset($data['error'])) {
            if (isset($data['odata.error']['message']['value'])) {
                $message = $data['odata.error']['message']['value'];
            } elseif (isset($data['error']['message'])) {
                $message = $data['error']['message'];
            } else {
                $message = $response->getReasonPhrase();
            }

            throw new IdentityProviderException(
                $message,
                $response->getStatusCode(),
                $response
            );
        }
    }

    protected function getDefaultScopes()
    {
        return $this->scope;
    }
    
    protected function createAccessToken(array $response, AbstractGrant $grant)
    {
        return new AccessToken($response, $this);
    }
    
    public function getResourceOwner(\League\OAuth2\Client\Token\AccessToken $token)
    {
        $data = $token->getIdTokenClaims();
        return $this->createResourceOwner($data, $token);
    }
    
    public function getResourceOwnerDetailsUrl(\League\OAuth2\Client\Token\AccessToken $token)
    {
        return null;
    }

    protected function createResourceOwner(array $response, \League\OAuth2\Client\Token\AccessToken $token)
    {
        return new AzureResourceOwner($response);
    }

    public function getObjects($tenant, $ref, &$accessToken, $headers = [])
    {
        $objects = [];
        
        if (filter_var($ref, FILTER_VALIDATE_URL) === FALSE) {
            $ref = $tenant."/".$ref;
        }
        
        $response = null;
		do {
        	$response = $this->get($ref, $accessToken, $headers);
            foreach ($response as $value) {
                $objects[] = $value;
            }
			if (isset($response['odata.nextLink'])) {
                $ref = $response['odata.nextLink'];
            } elseif (isset($response['@odata.nextLink'])) {
                $ref = $response['@odata.nextLink'];
            }
			else {
				$ref = null;
			}
		} while ($ref != null);
        
        return $objects;
    }

    public function get($ref, &$accessToken, $headers = [])
    {
        $response = $this->request('get', $ref, $accessToken, ['headers' => $headers]);

        return $this->wrapResponse($response);
    }

    public function post($ref, $body, &$accessToken, $headers = [])
    {
        $response = $this->request('post', $ref, $accessToken, ['body' => $body, 'headers' => $headers]);

        return $this->wrapResponse($response);
    }

    public function put($ref, $body, &$accessToken, $headers = [])
    {
        $response = $this->request('put', $ref, $accessToken, ['body' => $body, 'headers' => $headers]);

        return $this->wrapResponse($response);
    }

    public function delete($ref, &$accessToken, $headers = [])
    {
        $response = $this->request('delete', $ref, $accessToken, ['headers' => $headers]);

        return $this->wrapResponse($response);
    }

    public function patch($ref, $body, &$accessToken, $headers = [])
    {
        $response = $this->request('patch', $ref, $accessToken, ['body' => $body, 'headers' => $headers]);

        return $this->wrapResponse($response);
    }

    private function request($method, $ref, &$accessToken, $options = [])
    {
        if ($accessToken->hasExpired()) {
            $accessToken = $this->getAccessToken('refresh_token', [
                'refresh_token' => $accessToken->getRefreshToken()
            ]);
        }

        $url = null;
        if (filter_var($ref, FILTER_VALIDATE_URL) !== FALSE) {
            $url = $ref;
        } else {
            $url = $this->resource.$ref;
        }

        if(isset($options['body']) && (gettype($options['body']) == 'array' || gettype($options['body']) == 'object')) {
            $options['body'] = json_encode($options['body']);
        }
        if(!isset($options['headers']['Content-Type']) && isset($options['body'])) {
            $options['headers']['Content-Type'] = 'application/json';
        }

        $request = $this->getAuthenticatedRequest($method, $url, $accessToken, $options);
        $response = $this->getResponse($request);

        return $response;
    }

    private function wrapResponse($response)
    {
        if (empty($response)) {
            return null;
        } elseif (isset($response['value'])) {
            return $response['value'];
        }

        return $response;
    }
    
    public function getClientId()
    {
        return $this->clientId;
    }
    
    /**
     * Obtain URL for logging out the user.
     *
     * @input $post_logout_redirect_uri string The URL which the user should be redirected to after logout
     *
     * @return string
     */
    public function getLogoutUrl($post_logout_redirect_uri = null, $policy = 'default')
    {
        $url = $this->openIdConfiguration[$policy]['token_endpoint'];
        if($post_logout_redirect_uri) {
            if(strpos($url, '?') !== FALSE) $url .= "&";
            else $url .= "?";
            $url .= 'post_logout_redirect_uri='.rawurlencode($post_logout_redirect_uri);
        }
        return $url;
    }
    
    /**
     * Validate the access token you received in your application.
     *
     * @input $accessToken string The access token you received in the authorization header.
     *
     * @return array
     */
    public function validateToken($accessToken, $idToken, $policy = 'default')
    {
        $keys = $this->getJwtVerificationKeys($this->openIdConfiguration['default']['jwks_uri']);
        
        $tokenClaims = null;
        try {
            $tks = explode('.', $idToken);
            // Check if the id_token contains signature
            if(count($tks) == 3 && !empty($tks[2])) {
                $tokenClaims = (array)JWT::decode($idToken, $keys, ['RS256']);
            }
            else {
                // The id_token is unsigned (coming from v1.0 endpoint) - https://msdn.microsoft.com/en-us/library/azure/dn645542.aspx
                // Validate the access_token signature first by parsing it as JWT into claims
                $accessTokenClaims = (array)JWT::decode($accessToken, $keys, ['RS256']);
                // Then parse the idToken claims only without validating the signature
                $tokenClaims = (array)JWT::jsonDecode(JWT::urlsafeB64Decode($tks[1]));
            }
        }  catch (JWT_Exception $e) {
            throw new RuntimeException("Unable to parse the id_token!");
        }
        
        if($this->getClientId() != $tokenClaims['aud']) {
            throw new RuntimeException("The audience is invalid!");
        }
        if($tokenClaims['nbf'] > time() || $tokenClaims['exp'] < time()) {
            // Additional validation is being performed in firebase/JWT itself
            throw new RuntimeException("The id_token is invalid!");
        }
        
        if(strpos($this->metadata, "common") !== FALSE) {
            $issuer = str_replace("{tenantid}", $tokenClaims['tid'], $this->openIdConfiguration['default']['issuer']);
            
            if($tokenClaims['iss'] != $issuer) {
                throw new RuntimeException("Invalid token issuer!");
            }
        }
        else {
            if($tokenClaims['iss'] != $this->openIdConfiguration['default']['issuer']) {
                throw new RuntimeException("Invalid token issuer!");
            }
        }
        
        return $tokenClaims;
    }
    
    public function getOpenIdConfiguration($metadata)
    {
        $factory = $this->getRequestFactory();
        $request = $factory->getRequestWithOptions('get', $metadata, []);
        
        $response = $this->getResponse($request);
        
        return $response;
    }
    
    /**
     * Get JWT verification keys from Azure Active Directory.
     *
     * @return array
     */
    public function getJwtVerificationKeys($endpoint)
    {
        $factory = $this->getRequestFactory();
        $request = $factory->getRequestWithOptions('get', $endpoint, []);
        
        $response = $this->getResponse($request);
        
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
}
