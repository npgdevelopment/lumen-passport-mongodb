<?php

namespace Kayrules\LumenPassport\Bridge;

use MoeenBasra\LaravelPassportMongoDB\Events\RefreshTokenCreated;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;

class RefreshTokenRepository extends \MoeenBasra\LaravelPassportMongoDB\Bridge\RefreshTokenRepository
{
    /**
     * {@inheritdoc}
     */
    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity)
    {
        $this->database->table('oauth_refresh_tokens')->insert([
            '_id' => $id = $refreshTokenEntity->getIdentifier(),
            'id' => $id,
            'access_token_id' => $accessTokenId = $refreshTokenEntity->getAccessToken()->getIdentifier(),
            'revoked' => false,
            'expires_at' => $refreshTokenEntity->getExpiryDateTime(),
        ]);

        $this->events->fire(new RefreshTokenCreated($id, $accessTokenId));
    }
}
