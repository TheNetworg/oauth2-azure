# Azure Active Directory Provider for OAuth 2.0 Client
[![Latest Version](https://img.shields.io/github/release/thenetworg/oauth2-azure.svg?style=flat-square)](https://github.com/thenetworg/oauth2-azure/releases)
[![Total Downloads](https://img.shields.io/packagist/dt/thenetworg/oauth2-azure.svg?style=flat-square)](https://packagist.org/packages/thenetworg/oauth2-azure)
[![Software License](https://img.shields.io/packagist/l/thenetworg/oauth2-azure.svg?style=flat-square)](LICENSE.md)

This package provides [Azure Active Directory](https://azure.microsoft.com/en-us/services/active-directory/) OAuth 2.0 support for the PHP League's [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

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
        printf('Hello %s!', $me['givenName']);

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

#### Using custom parameters

With [oauth2-client](https://github.com/thephpleague/oauth2-client) of version 1.3.0 and higher, it is now possible to specify custom parameters for the authorization URL, so you can now make use of options like `prompt`, `login_hint` and similar. See the following example of obtaining an authorization URL which will force the user to reauthenticate:
```php
$authUrl = $provider->getAuthorizationUrl([
    'prompt' => 'login'
]);
```
You can find additional parameters [here](https://msdn.microsoft.com/en-us/library/azure/dn645542.aspx).

## Making API Requests

This library also provides easy interface to make it easier to interact with [Azure Graph API](https://msdn.microsoft.com/en-us/library/azure/hh974476.aspx) and [Microsoft Graph](http://graph.microsoft.io), the following methods are available on `provider` object (it also handles automatic token refresh flow should it be needed during making the request):

- `get($ref, $accessToken, $headers = [])`
- `post($ref, $body, $accessToken, $headers = [])`
- `put($ref, $body, $accessToken, $headers = [])`
- `delete($ref, $body, $accessToken, $headers = [])`
- `patch($ref, $body, $accessToken, $headers = [])`
- `getObjects($tenant, $ref, $accessToken, $objects = [], $headers = [])` This is used for example for listing large amount of data - where you need to list all users for example - it automatically follows `odata.nextLink` until the end.
  - `$tenant` tenant has to be provided since the `odata.nextLink` doesn't contain it.
  - `$objects` should be either an empty array or a set of data which will be included in the results

*Please note that if you need to create a custom request, the method getAuthenticatedRequest and getResponse can still be used.*

### Variables
- `$ref` The URL reference without the leading `/`, for example `myOrganization/groups`
- `$body` The contents of the request, make has to be either string (so make sure to use `json_encode` to encode the request)s or stream (see [Guzzle HTTP](http://docs.guzzlephp.org/en/latest/request-options.html#body))
- `$accessToken` The access token object obtained by using `getAccessToken` method
- `$headers` Ability to set custom headers for the request (see [Guzzle HTTP](http://docs.guzzlephp.org/en/latest/request-options.html#headers))

## Resource Owner
With version 1.1.0 and onward, the Resource Owner information is parsed from the JWT passed in `access_token` by Azure Active Directory. It exposes few attributes and one function.

**Example:**
```php
$resourceOwner = $provider->getResourceOwner($token);
echo 'Hello, '.$resourceOwner->getFirstName().'!';
```
The exposed attributes and function are:
- `getId()` - Gets user's object id - unique for each user
- `getFirstName()` - Gets user's first name
- `getLastName()` - Gets user's family name/surname
- `getTenantId()` - Gets id of tenant which the user is member of
- `getUpn()` - Gets user's User Principal Name, which can be also used as user's e-mail address
- `getClaim($name)` - Gets any other claim (specified as `$name`) from the JWT, full list can be found [here](https://azure.microsoft.com/en-us/documentation/articles/active-directory-token-and-claims/)

## Microsoft Graph
Calling [Microsoft Graph](http://graph.microsoft.io/) is very simple with this library. After provider initialization simply change the API URL followingly (replace `v1.0` with your desired version):
```php
$provider->urlAPI = "https://graph.microsoft.com/v1.0/";
```
After that, when requesting access token, refresh token or so, provide the `resource` with value `https://graph.microsoft.com/` in order to be able to make calls to the Graph (see more about `resource` [here](#advanced-flow)).

## Azure Active Directory B2C - *experimental*
You can also now very simply make use of [Azure Active Directory B2C](https://azure.microsoft.com/en-us/documentation/articles/active-directory-b2c-reference-oauth-code/). Before authentication, change the endpoints using `pathAuthorize`, `pathToken` and `scope` and additionally specify your [login policy](https://azure.microsoft.com/en-gb/documentation/articles/active-directory-b2c-reference-policies/). **Please note that the B2C support is still experimental and wasn't fully tested.**
```php
$provider->pathAuthorize = "/oauth2/v2.0/authorize";
$provider->pathToken = "/oauth2/v2.0/token";
$provider->scope = ["idtoken"];

//specify custom policy in our authorization URL
$authUrl = $provider->getAuthorizationUrl([
    'p' => 'b2c_1_siup'
]);
```

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
