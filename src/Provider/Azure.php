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

    protected $metadata = "https://login.microsoftonline.com/common/.well-known/openid-configuration";

    public $resource = null;
    
    protected $audience = null;
    
    protected $responseType = 'code';
    protected $responseMode;
    
    public $openIdConfiguration = null;

    public function __construct(array $options = [], array $collaborators = [])
    {
        if(isset($options['metadata'])) {
            $this->metadata = $options['metadata'];
        }
        if(isset($options['responseType'])) {
            $this->responseType = $options['responseType'];
        }
        if(isset($options['responseMode'])) {
            $this->responseMode = $options['responseMode'];
        }
        if(isset($options['audience'])) {
            $this->audience = $options['audience'];
        }
        
        parent::__construct($options, $collaborators);
        $this->grantFactory->setGrant('jwt_bearer', new JwtBearer);
        $this->openIdConfiguration = $this->getOpenIdConfiguration($this->metadata);
    }

    public function getBaseAuthorizationUrl()
    {
        return $this->openIdConfiguration['authorization_endpoint'];
    }

    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->openIdConfiguration['token_endpoint'];
    }
    
    public function getAccessToken($grant, array $options = [])
    {
        // If we are requesting a resource (set as $provider->resource) or passing it on our own in case of multipurpose refresh tokens
        if($this->resource != null && !isset($options['resource'])) {
            $options['resource'] = $this->resource;
        }
        return parent::getAccessToken($grant, $options);
    }
    
    protected function getAuthorizationParameters(array $options)
    {
        if (empty($options['state'])) {
            $options['state'] = $this->getRandomState();
        }
        if (empty($options['scope'])) {
            $options['scope'] = $this->getDefaultScopes();
        }
        $options['response_type'] = $this->responseType;
        if(isset($this->responseMode)) $options['response_mode'] = $this->responseMode;
        if (is_array($options['scope'])) {
            $separator = $this->getScopeSeparator();
            $options['scope'] = implode($separator, $options['scope']);
        }
        // Store the state as it may need to be accessed later on.
        $this->state = $options['state'];
        $options['client_id'] = $this->clientId;
        $options['redirect_uri'] = $this->redirectUri;
        $options['state'] = $this->state;
        
        return $options;
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
        return [];
    }

  	protected function getScopeSeparator()
  	{
  		return ' ';
  	}
    
    protected function createAccessToken(array $response, AbstractGrant $grant)
    {
        return new AccessToken($response, $this);
    }
    
    public function createToken(array $response)
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
        
        $response = null;
        do {
            if (filter_var($ref, FILTER_VALIDATE_URL) === FALSE) {
                $ref = $tenant."/".$ref;
            }
            
            $response = $this->request('get', $ref, $accessToken, ['headers' => $headers]);
            $values = $response;
            if(isset($response['value'])) $values = $response['value'];
            foreach ($values as $value) {
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

    public function request($method, $ref, &$accessToken, $options = [])
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
    
    protected function appendQuery($url, $query)
    {
        $query = trim($query, '?&');
        if ($query) {
            if(strpos($url, '?') !== FALSE) return $url."&".$query;
            else return $url."?".$query;
        }
        return $url;
    }
    
    /**
     * Obtain URL for logging out the user.
     *
     * @input $post_logout_redirect_uri string The URL which the user should be redirected to after logout
     *
     * @return string
     */
    public function getLogoutUrl($post_logout_redirect_uri = null)
    {
        $url = $this->openIdConfiguration['end_session_endpoint'];
        if($post_logout_redirect_uri) {
            if(strpos($url, '?') !== FALSE) $url .= "&";
            else $url .= "?";
            $url .= 'post_logout_redirect_uri='.rawurlencode($post_logout_redirect_uri);
        }
        return $url;
    }
    
    /**
     * Validate the ID token you received in your application.
     *
     * @input $id_token string The ID token you received in the authorization header.
     *
     * @return array
     */
    public function validateToken($id_token)
    {
        $jwks = $this->getJwtVerificationKeys($this->openIdConfiguration['jwks_uri']);
        $jwt = null;
        $last_exception = null;

        foreach ($jwks['keys'] as $i => $key) {
            try {
				        if ( null == $key['x5c'] ) {
					          throw new \RuntimeException( 'key does not contain the x5c attribute' );
				        }
								$key_der = $key['x5c'][0];
				        $key_pem = chunk_split( $key_der, 64, "\n" );
				        $key_pem = "-----BEGIN CERTIFICATE-----\n" . $key_pem  . "-----END CERTIFICATE-----\n";
				        $jwt = (array) JWT::decode( $id_token, $key_pem, array('HS256','HS384','HS512','RS256'));
				        break;
			      } catch ( Exception $e ) {
				        $last_exception = $e;
			      }
		    }
		    if ( null == $jwt ) {
			      throw $last_exception;
		    }
        if ($this->audience && $this->audience != $jwt['aud']) {
            throw new \RuntimeException("The audience is invalid!");
        }
        if ($this->openIdConfiguration['issuer'] != $jwt['iss']) {
            throw new \RuntimeException("The security token service is invalid!");
        }
        return $jwt;
    }

    /**
	   * Get OAuth2 URLs from Azure Active Directory.
	   *
	   * @return array
	   */
    public function getOpenIdConfiguration($metadata)
    {
        $factory = $this->getRequestFactory();
        $request = $factory->getRequestWithOptions('get', $metadata, []);
        
        $response = $this->getResponse($request);
        
        return json_decode($response->getBody(),true);
    }

    private function convert_base64url_to_base64($data) {
		return str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT);
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
        
        return json_decode($response->getBody(),true);
    }
}
