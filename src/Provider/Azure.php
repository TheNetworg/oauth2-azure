<?php
namespace TheNetworg\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;

class Azure extends AbstractProvider {
    use BearerAuthorizationTrait;
    
	public $urlLogin = "https://login.microsoftonline.com/";
    public $tenant = "common";
	public $urlAPI = "https://graph.windows.net/";
	public $API_VERSION = "1.6";
	
    public function getBaseAuthorizationUrl() {
        return $this->urlLogin.$this->tenant."/oauth2/authorize";
    }
	
    public function getBaseAccessTokenUrl(array $params) {
        return $this->urlLogin.$this->tenant."/oauth2/token";
    }
	
    protected function checkResponse(ResponseInterface $response, $data) {
        if(isset($data->{'odata.error'})) {
            throw new IdentityProviderException(
                (isset($data->{'odata.error'}->message) ? $data->{'odata.error'}->message : $response->getReasonPhrase()),
                $response->getStatusCode(),
                $response
            );
        }
    }
	
    protected function getDefaultScopes() {
        return [];
    }
    
    protected function createResourceOwner(array $response, AccessToken $token) {
        return new AzureResourceOwner($response);
    }
	
    public function getResourceOwnerDetailsUrl(AccessToken $token) {
        return "me";
    }
	
    public function getObjects($tenant, $ref, $objects = [], $accessToken) {
        $response = $this->request('GET', $tenant."/".$ref, $accessToken, []);
		if($response) {
			$values = $response->value;
			foreach($values as $value) {
				$objects[] = $value;
			}
			if(isset($response->{'odata.nextLink'})) {
				$nextLink = $response->{'odata.nextLink'};
				return $this->getObjects($tenant, $nextLink, $objects, $accessToken);
			}
			else {
				return $objects;
			}
		}
    }
	public function get($ref, $accessToken) {
        $response = $this->request('get', $ref, $accessToken);
        return $this->wrapResponse($response);
    }
    public function post($ref, $body, $accessToken) {
        $response = $this->request('post', $ref, $accessToken, ['body' => $body]);
        return $this->wrapResponse($response);
    }
    public function put($ref, $body, $accessToken) {
        $response = $this->request('put', $ref, $accessToken, ['body' => $body]);
        return $this->wrapResponse($response);
    }
    public function delete($ref, $accessToken) {
        $response = $this->request('delete', $ref, $accessToken);
        return $this->wrapResponse($response);
    }
    public function patch($ref, $body, $accessToken) {
        $response = $this->request('patch', $ref, $accessToken, ['body' => $body]);
        return $this->wrapResponse($response);
    }
    
    private function request($method, $ref, $accessToken, $options = []) {
        $url = $this->urlAPI.$ref;
        
        $url .= (strrpos($url, "?") === FALSE) ? "?" : "&";
        $url .= "api-version=".$this->API_VERSION;
        
        $request = $this->getAuthenticatedRequest($method, $url, $accessToken, $options);
        $response = $this->getResponse($request);
        
        return $response;
    }
    
    private function wrapResponse($response) {
        if(empty($response)) return null;
		else if(isset($response->value)) return $response->value;
		else return $response;
    }
    
    public function getClientId() {
        return $this->clientId;
    }
}