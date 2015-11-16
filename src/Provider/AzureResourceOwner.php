<?php

namespace TheNetworg\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class AzureResourceOwner implements ResourceOwnerInterface
{
    /**
     * Response payload
     *
     * @var array
     */
    protected $response;

    /**
     * Creates new azure resource owner.
     *
     * @param array  $response
     */
    public function __construct($response = [])
    {
        $this->response = $response;
    }

    /**
     * Retrieves id of azure resource owner.
     *
     * @return string|null
     */
    public function getId()
    {
        return $this->response['objectId'] ?: null;
    }
}
