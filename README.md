# Azure Active Directory Provider for OAuth 2.0 Client
[![Latest Version](https://img.shields.io/github/release/thenetworg/oauth2-azure.svg?style=flat-square)](https://github.com/thenetworg/oauth2-azure/releases)
[![Latest Unstable Version](https://img.shields.io/packagist/vpre/thenetworg/oauth2-azure.svg?label=pre-release&style=flat-square)](https://packagist.org/packages/thenetworg/oauth2-azure)
[![Total Downloads](https://img.shields.io/packagist/dt/thenetworg/oauth2-azure.svg?style=flat-square)](https://packagist.org/packages/thenetworg/oauth2-azure)
[![Software License](https://img.shields.io/packagist/l/thenetworg/oauth2-azure.svg?style=flat-square)](LICENSE.md)

This package provides [Azure Active Directory](https://azure.microsoft.com/en-us/services/active-directory/) OAuth 2.0 support for the PHP League's [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

> The latest release of this package is specifically designed to support Azure Active Directory OAuth 2.0 support when using the OAuth 2.0 Client ~1.0.

## Installation

To install, use composer:

```
composer require thenetworg/oauth2-azure
```

## Usage

Usage is the same as The League's OAuth client, using `\TheNetworg\OAuth2\Client\Provider\Azure` as the provider.

### Authorization Code Flow

```php
$provider = new TheNetworg\OAuth2\Client\Provider\Azure([
    'clientId'          => '{azure-client-id}',
    'clientSecret'      => '{azure-client-secret}',
    'redirectUri'       => 'https://example.com/callback-url'
]);

if (!isset($_GET['code'])) {

    // If we don't have an authorization code then get one
    $authUrl = $provider->getAuthorizationUrl();
    $_SESSION['oauth2state'] = $provider->getState();
    header('Location: '.$authUrl);
    exit;

// Check given state against previously stored one to mitigate CSRF attack
} elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {

    unset($_SESSION['oauth2state']);
    exit('Invalid state');

} else {

    // Try to get an access token (using the authorization code grant)
    $token = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code'],
        'resource' => 'https://graph.windows.net'
    ]);

    // Optional: Now you have a token you can look up a users profile data
    try {

        // We got an access token, let's now get the user's details
        $me = $provider->get("me", $token);

        // Use these details to create a new profile
        printf('Hello %s!', $me->first_name);

    } catch (Exception $e) {

        // Failed to get user details
        exit('Oh dear...');
    }

    // Use this to interact with an API on the users behalf
    echo $token->getToken();
}
```

#### Advanced flow

The [Authorization Code Grant Flow](https://msdn.microsoft.com/en-us/library/azure/dn645542.aspx) is a little bit different for Azure Active Directory. Instead of scopes, you specify the resource which you would like to access - see the above example where `resource` is specified when obtaining access token from the code.

## Making API Requests

This library also provides easy interface to make it easier to interact with [Azure Graph API](https://msdn.microsoft.com/en-us/library/azure/hh974476.aspx), the following methods are available on `provider` object:

- `get($ref, $accessToken)`
- `post($ref, $body, $accessToken)`
- `put($ref, $body, $accessToken)`
- `delete($ref, $body, $accessToken)`
- `patch($ref, $body, $accessToken)`
- `getObjects($tenant, $ref, $accessToken, $objects = [])` This is used for example for listing large amount of data - where you need to list all users for example - it automatically follows `odata.nextLink` until the end.
  - `$tenant` tenant has to be provided since the `odata.nextLink` doesn't contain it.
  - `$objects` should be either an empty array or a set of data which will be included in the results

*Please not that if you need to create a custom request, the method getAuthenticatedRequest and getResponse can still be used*

### Variables
- `$ref` The URL reference without the leading `/`, for example `myOrganization/groups`
- `$body` The contents of the request, for example an object or so, it will be automatically converted to JSON
- `$accessToken` The access token object obtained by using `getAccessToken` method

## Microsoft Graph
Calling [Microsoft Graph](http://graph.microsoft.io/) is very simple with this library. After provider initialization simply change the API URL followingly (replace `v1.0` with your desired version):
```php
$app->OAuth2->provider->urlAPI = "https://graph.microsoft.com/v1.0/";
```
After that, when requesting access token, refresh token or so, provide the `resource` with value `https://graph.microsoft.com/` in order to be able to make calls to the Graph (see more about `resource` [here](#advanced-flow)).

## Known users
If you are using this library and would like to be listed here, please let us know!
- [TheNetworg/DreamSpark-SSO](https://github.com/thenetworg/dreamspark-sso)

## Contributing
Contributions are **welcome** and will be fully **credited**.

We accept contributions via [Pull Requests on Github](https://github.com/thenetworg/oauth2-azure).


## Credits
- [Jan Hajek](https://github.com/hajekj) ([TheNetw.org](https://thenetw.org))
- [All Contributors](https://github.com/thenetworg/oauth2-azure/contributors)

## Support
If you find a bug or encounter any issue or have a problem/question with this library please create a [new issue](https://github.com/TheNetworg/oauth2-azure/issues).

## License
The MIT License (MIT). Please see [License File](https://github.com/thenetworg/oauth2-azure/blob/master/LICENSE) for more information.
