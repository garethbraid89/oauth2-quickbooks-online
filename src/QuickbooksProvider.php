<?php

namespace Compwright\OAuth2_Quickbooks_Online;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

class QuickbooksProvider extends AbstractProvider
{
    use BearerAuthorizationTrait;

    public const SCOPE_ACCOUNTING = 'com.intuit.quickbooks.accounting';

    public const API_URL_PRODUCTION = 'https://quickbooks.api.intuit.com';

    public const API_URL_SANDBOX = 'https://sandbox-quickbooks.api.intuit.com';

    private string $apiUrl = self::API_URL_PRODUCTION;

    private string $minorVersion = '69';

    protected ?string $realmId = null;

    /**
     * @param string $apiUrl
     * @return QuickbooksProvider
     */
    public function setApiUrl(string $apiUrl): self
    {
        $this->apiUrl = $apiUrl;
        return $this;
    }

    public function setApiMinorVersion(string $minorVersion): self
    {
        $this->minorVersion = $minorVersion;
        return $this;
    }

    public function getBaseAuthorizationUrl(): string
    {
        return 'https://appcenter.intuit.com/connect/oauth2';
    }

    public function getBaseAccessTokenUrl(array $params): string
    {
        /**
         * Quickbooks Online's OAuth 2.0 redirect will include a `realmId` parameter
         * in the URL. If this is included along with `state` in the options provided
         * to getAccessToken(), we need to capture it here for inclusion later as the
         * resource owner ID in the AccessToken.
         */
        if (isset($params['realmId'])) {
            $this->realmId = $params['realmId'];
        }

        return 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer';
    }

    protected function prepareAccessTokenResponse(array $result): array
    {
        $result = parent::prepareAccessTokenResponse($result);

        /**
         * Add the realmId to the access token response since this is provided in the
         * redirect URL instead of the token API response.
         */
        if ($this->realmId) {
            $result['resource_owner_id'] = $this->realmId;
        }

        return $result;
    }

    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        if (!$token->getResourceOwnerId()) {
            throw new RuntimeException(
                'Missing realmId, please include this URL parameter in the options to getAccessToken()'
            );
        }

        return sprintf(
            '%s/v3/company/%s/companyinfo/%s?minorversion=%s',
            $this->apiUrl,
            $token->getResourceOwnerId(),
            $token->getResourceOwnerId(),
            $this->minorVersion
        );
    }

    public function getDefaultScopes(): array
    {
        return [self::SCOPE_ACCOUNTING];
    }

    public function checkResponse(ResponseInterface $response, $data): void
    {
        if (!empty($data['errors'])) {
            throw new IdentityProviderException($data['errors'], 0, $data);
        }
    }

    protected function createResourceOwner(array $response, AccessToken $token): QuickbooksCompany
    {
        return new QuickbooksCompany($response, $token->getResourceOwnerId());
    }

    /**
     * @inheritdoc
     */
    protected function getDefaultHeaders(): array
    {
        return [
            'Accept' => 'application/json',
        ];
    }
}
