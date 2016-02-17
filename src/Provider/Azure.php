<?php

namespace TheNetworg\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;

class Azure extends AbstractProvider
{
    use BearerAuthorizationTrait;

    public $urlLogin = "https://login.microsoftonline.com/";

    public $tenant = "common";

    public $urlAPI = "https://graph.windows.net/";

    public $API_VERSION = "1.6";

    public function getBaseAuthorizationUrl()
    {
        return $this->urlLogin.$this->tenant."/oauth2/authorize";
    }

    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->urlLogin.$this->tenant."/oauth2/token";
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

    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new AzureResourceOwner($response);
    }

    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return "me";
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
            $url .= (strrpos($url, "?") === false) ? "?" : "&";
            $url .= "api-version=".$this->API_VERSION;
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
