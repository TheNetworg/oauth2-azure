<?php
namespace TheNetworg\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class AzureResourceOwner implements ResourceOwnerInterface
{
    protected $response;

    public function __construct($response = []) {
        $this->response = $response;
    }
	
    public function getId() {
        return $this->response['objectId'] ?: null;
    }
}

