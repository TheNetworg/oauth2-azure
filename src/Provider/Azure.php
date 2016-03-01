<?php

namespace TheNetworg\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;
use \Firebase\JWT\JWT;

class Azure extends AbstractProvider
{
    use BearerAuthorizationTrait;

    public $urlLogin = "https://login.microsoftonline.com/";
    public $pathAuthorize = "/oauth2/authorize";
    public $pathToken = "/oauth2/token";
    
    public $scope = [];

    public $tenant = "common";

    public $urlAPI = "https://graph.windows.net/";

    public $API_VERSION = "1.6";

    public function getBaseAuthorizationUrl()
    {
        return $this->urlLogin.$this->tenant.$this->pathAuthorize;
    }

    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->urlLogin.$this->tenant.$this->pathToken;
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
    
    /**
     * Get JWT verification keys from Azure Active Directory.
     *
     * @return array
     */
    private function getJwtVerificationKeys()
    {
        $factory = $this->getRequestFactory();
        $request = $factory->getRequestWithOptions('get', 'https://login.windows.net/common/discovery/keys', []);
        
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
    
    public function getResourceOwner(AccessToken $token)
    {
        $jwt = (string) $token;
        try {
            $keys = $this->getJwtVerificationKeys();
            $values = (array)JWT::decode($token, $keys, ['RS256']);
        }  catch (JWT_Exception $e) {
            $values = [];
        }
        return $this->createResourceOwner($values, $token);
    }
    
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return null;
    }

    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new AzureResourceOwner($response);
    }

    public function getObjects($tenant, $ref, &$accessToken, $objects = [], $headers = [])
    {
        if (filter_var($ref, FILTER_VALIDATE_URL) === FALSE) {
            $ref = $tenant."/".$ref;
        }
        $response = $this->request('GET', $ref, $accessToken, ['headers' => $headers]);

        if ($response) {
            $values = $response['value'];
            foreach ($values as $value) {
                $objects[] = $value;
            }
            
            if (isset($response['odata.nextLink'])) {
                $nextLink = $response['odata.nextLink'];
            } elseif (isset($response['@odata.nextLink'])) {
                $nextLink = $response['@odata.nextLink'];
            } else {
                return $objects;
            }
            return $this->getObjects($tenant, $nextLink, $accessToken, $objects);
        }
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
            $accessToken = $app->OAuth2->provider->getAccessToken('refresh_token', [
                'refresh_token' => $app->OAuth2->token->getRefreshToken(),
                'resource' => $this->urlAPI
            ]);
        }

        $url = null;
        if (filter_var($ref, FILTER_VALIDATE_URL) !== FALSE) {
            $url = $ref;
        } else {
            $url = $this->urlAPI.$ref;

            if (strpos($this->urlAPI, "graph.microsoft.com") === FALSE) {
                $url .= (strrpos($url, "?") === false) ? "?" : "&";
                $url .= "api-version=".$this->API_VERSION;
            }
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
}
