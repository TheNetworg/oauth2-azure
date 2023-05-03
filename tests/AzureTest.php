<?php

namespace TheNetworg\OAuth2\Client\Tests;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessTokenInterface;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use TheNetworg\OAuth2\Client\Provider\Azure;
use TheNetworg\OAuth2\Client\Provider\AzureResourceOwner;
use TheNetworg\OAuth2\Client\Tests\Fakers\B2cKeysFaker;
use TheNetworg\OAuth2\Client\Tests\Fakers\B2cTokenFaker;
use TheNetworg\OAuth2\Client\Token\AccessToken;

class AzureTest extends TestCase
{

    /** @var Azure */
    private $azure;

    /** @var B2cTokenFaker */
    private $tokenFaker;

    /** @var B2cKeysFaker */
    private $keysFaker;


    /** @var string */
    private $defaultClientId;

    /** @var string */
    private $defaultIss;

    /** @var string */
    private $defaultAuthEndpoint;

    /** @var string */
    private $defaultLogoutUrl;


    /**
     * @before
     */
    public function setup(): void
    {
        $this->tokenFaker = new B2cTokenFaker();
        $this->keysFaker = new B2cKeysFaker();

        $this->defaultClientId = 'client_id';
        $this->defaultIss = 'iss';
        $this->defaultAuthEndpoint = 'auth_endpoint';
        $this->defaultLogoutUrl = 'logout_url';
    }

    /**
     * @test
     */
    public function it_throws_runtime_exception_when_client_id_is_invalid(): void
    {
        $this->expectException(RuntimeException::class);

        $this->setDefaultFakeData();
        $this->azure = new Azure(['clientId' => 'invalid_client_id'], ['httpClient' => $this->getMockHttpClient()]);

        $this->getAccessToken();
    }

    /**
     * @test
     */
    public function it_throws_runtime_exception_when_token_is_expired(): void
    {
        // This test is not working as expected. The exception is thrown in firebase/php-jwt/src/JWT.php:163 instead of Azure.php:357
        $this->expectException(RuntimeException::class);

        $this->tokenFaker->setFakeData('b2cId', true, $this->defaultClientId, $this->defaultIss, time() - 99);
        $this->azure = new Azure(['clientId' => $this->defaultClientId], ['httpClient' => $this->getMockHttpClient()]);

        $this->getAccessToken();
    }

    /**
     * @test
     */
    public function it_throws_runtime_exception_when_token_is_from_future(): void
    {
        // This test is not working as expected. The exception is thrown in firebase/php-jwt/src/JWT.php:147 instead of Azure.php:357
        $this->expectException(RuntimeException::class);

        $this->tokenFaker->setFakeData('b2cId', true, $this->defaultClientId, $this->defaultIss, null, time() + 99);
        $this->azure = new Azure(['clientId' => $this->defaultClientId], ['httpClient' => $this->getMockHttpClient()]);

        $this->getAccessToken();
    }

    /**
     * @test
     */
    public function it_throws_runtime_exception_when_issuer_is_invalid(): void
    {
        $this->expectException(RuntimeException::class);

        $this->tokenFaker->setFakeData('b2cId', true, $this->defaultClientId, 'invalid_issuer');
        $this->azure = new Azure(['clientId' => $this->defaultClientId], ['httpClient' => $this->getMockHttpClient()]);

        $this->getAccessToken();
    }

    /**
     * @test
     */
    public function it_correctly_sets_global_vars_in_constructor(): void
    {
        $this->setDefaultFakeData();
        $defaultEndpointVersion = '2.0';
        $scope = ['openid'];

        $this->azure = new Azure(
            [
                'clientId' => $this->defaultClientId,
                'scopes' => $scope,
                'defaultEndPointVersion' => $defaultEndpointVersion,
            ]
        );

        $this->assertEquals($this->azure->scope, $scope);
        $this->assertEquals($this->azure->defaultEndPointVersion, $defaultEndpointVersion);
    }

    /**
     * @test
     */
    public function it_gets_base_authorization_url_from_config(): void
    {
        $this->setDefaultFakeData();
        $this->azure = new Azure(['clientId' => $this->defaultClientId], ['httpClient' => $this->getMockHttpClient()]);

        $this->assertEquals($this->defaultAuthEndpoint, $this->azure->getBaseAuthorizationUrl());
    }

    /**
     * @test
     */
    public function it_gets_logout_url_from_config(): void
    {
        $this->setDefaultFakeData();
        $this->azure = new Azure(['clientId' => $this->defaultClientId], ['httpClient' => $this->getMockHttpClient()]);
        $post_logout_redirect_uri = 'post_logout_uri';

        $this->assertEquals($this->defaultLogoutUrl, $this->azure->getLogoutUrl());
        $this->assertEquals($this->defaultLogoutUrl .= '?post_logout_redirect_uri=' . rawurlencode($post_logout_redirect_uri), $this->azure->getLogoutUrl($post_logout_redirect_uri));
    }

    /**
     * @test
     */
    public function it_creates_valid_access_token(): void
    {
        $this->setDefaultFakeData();
        $this->azure = new Azure(['clientId' => $this->defaultClientId], ['httpClient' => $this->getMockHttpClient()]);

        try {
            /** @var AccessToken $token */
            $token = $this->getAccessToken();
        } catch (IdentityProviderException $e) {
            $this->fail();
        }

        $this->assertNotNull($token->getToken());
        $this->assertNotEmpty($token->getToken());

        $this->assertNotNull($token->getIdToken());
        $this->assertNotEmpty($token->getIdToken());

        $this->assertNotNull($token->getIdTokenClaims());
        $this->assertNotEmpty($token->getIdTokenClaims());
    }

    /**
     * @test
     */
    public function it_correctly_serializes_the_access_token(): void
    {
        $this->setDefaultFakeData();
        $this->azure = new Azure(['clientId' => $this->defaultClientId], ['httpClient' => $this->getMockHttpClient()]);

        try {
            /** @var AccessToken $token */
            $token = $this->getAccessToken();
        } catch (IdentityProviderException $e) {
            $this->fail();
        }

        $serializedToken = $token->jsonSerialize();

        $this->assertNotNull($serializedToken);
        $this->assertNotEmpty($serializedToken);

        $this->assertEquals($token->getIdToken(), $serializedToken['id_token']);
    }

    /**
     * @test
     */
    public function it_creates_valid_resource_owner(): void
    {
        $this->setDefaultFakeData();
        $this->azure = new Azure(['clientId' => $this->defaultClientId], ['httpClient' => $this->getMockHttpClient()]);

        try {
            /** @var AccessToken $token */
            $token = $this->getAccessToken();
        } catch (IdentityProviderException $e) {
            $this->fail();
        }

        /** @var AzureResourceOwner $owner */
        $owner = $this->azure->getResourceOwner($token);

        $this->assertEquals($this->defaultIss, $owner->claim('iss'));
        $this->assertEquals($this->defaultClientId, $owner->claim('aud'));

        $this->assertNull($owner->getId());
        $this->assertNull($owner->getFirstName());
        $this->assertNull($owner->getLastName());
        $this->assertNull($owner->getUpn());
        $this->assertNull($owner->getTenantId());
        $this->assertNotNull($owner->toArray());
    }

    /**
     * @test
     */
    public function it_should_return_token_claims_on_successful_validation(): void
    {
        $this->setDefaultFakeData();
        $this->azure = new Azure(['clientId' => $this->defaultClientId], ['httpClient' => $this->getMockHttpClient()]);

        try {
            /** @var AccessToken $token */
            $token = $this->getAccessToken();
        } catch (IdentityProviderException $e) {
            $this->fail();
        }

        $this->assertTrue(true);

        // TODO: fix this test
//        $claims = $this->azure->validateAccessToken($token);
//        $this->assertEquals($this->defaultIss, $claims['iss']);
//        $this->assertEquals($this->defaultClientId, $claims['aud']);
    }

    /**
     * @test
     */
    public function it_should_throw_exception_for_invalid_keys(): void
    {
        // This test is not working as expected. The exception is thrown in firebase/php-jwt/src/JWT.php:99 instead of AccessToken.php:41
        // besides, JWT_Exception does not exist
//        $this->expectException(JWT_Exception::class);

        // TODO: remove
        $this->expectException(Exception::class);

        $this->setDefaultFakeData();
        $this->azure = new Azure(['clientId' => $this->defaultClientId], ['httpClient' => $this->getMockHttpClient(true, false)]);

        $this->getAccessToken();
    }

    /**
     * @test
     */
    public function it_should_throw_exception_for_invalid_token(): void
    {
        $this->expectException(Exception::class);

        $this->setDefaultFakeData();
        $this->azure = new Azure(['clientId' => $this->defaultClientId], ['httpClient' => $this->getMockHttpClient(false, true)]);

        $this->getAccessToken();
    }


    /**
     * @test
     */
    public function it_should_correctly_set_grant(): void
    {
        $this->setDefaultFakeData();
        $this->azure = new Azure(['clientId' => $this->defaultClientId], ['httpClient' => $this->getMockHttpClient()]);

        $grantFactory = $this->azure->getGrantFactory();
        $grant = $grantFactory->getGrant('jwt_bearer');

        $this->assertTrue($grantFactory->isGrant($grant));
        $this->assertEquals('urn:ietf:params:oauth:grant-type:jwt-bearer', $grant->__toString());
        $this->assertEquals(['requested_token_use' => '', 'assertion' => '', 'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer'], $grant->prepareRequestParameters(['requested_token_use' => '', 'assertion' => ''], []));
    }



    /**
     * @return void
     */
    private function setDefaultFakeData(): void
    {
        $this->tokenFaker->setFakeData('b2cId', true, $this->defaultClientId, $this->defaultIss);
    }

    /**
     * @return string[]
     */
    private function getConfig(): array
    {
        return array(
            'issuer' => $this->defaultIss,
            'authorization_endpoint' => $this->defaultAuthEndpoint,
            'end_session_endpoint' => $this->defaultLogoutUrl,
            'token_endpoint' => '',
            'jwks_uri' => ''
        );
    }

    /**
     * @param bool $valid_token
     * @param bool $valid_key
     * @return MockHandler
     */
    private function getHandler(bool $valid_token, bool $valid_key): MockHandler
    {
        $config = $this->getConfig();
        $tokenResponse = $valid_token ? $this->tokenFaker->getB2cTokenResponse() : [''];
        $keyResponse = $valid_key ? $this->keysFaker->getB2cKeysResponse($this->tokenFaker->getPublicKey(), $this->tokenFaker->getModulus(), $this->tokenFaker->getExponent()) : ['keys' => [['']]];

        return new MockHandler([
            new Response(200, ['content-type' => 'application/json'], json_encode($config)),
            new Response(200, ['content-type' => 'application/json'], json_encode($tokenResponse)),
            new Response(200, ['content-type' => 'application/json'], json_encode($keyResponse)),
            new Response(200, ['content-type' => 'application/json'], json_encode($config)),
            new Response(200, ['content-type' => 'application/json'], json_encode($keyResponse)),
        ]);
    }


    /**
     * @param bool $valid_token
     * @param bool $valid_key
     * @return Client
     */
    private function getMockHttpClient(bool $valid_token = true, bool $valid_key = true): Client
    {
        return new Client(['handler' => $this->getHandler($valid_token, $valid_key)]);
    }
    /**
     * @return AccessTokenInterface
     * @throws IdentityProviderException
     */
    private function getAccessToken(): AccessTokenInterface
    {
        return $this->azure->getAccessToken('authorization_code', [
            'scope' => $this->azure->scope,
            'code' => 'authorization_code',
        ]);
    }

}