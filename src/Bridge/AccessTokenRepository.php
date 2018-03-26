<?php

namespace Kayrules\LumenPassport\Bridge;

use DateTime;
use MoeenBasra\LaravelPassportMongoDB\TokenRepository;
use Illuminate\Contracts\Events\Dispatcher;
use MoeenBasra\LaravelPassportMongoDB\Events\AccessTokenCreated;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;

class AccessTokenRepository extends \MoeenBasra\LaravelPassportMongoDB\Bridge\AccessTokenRepository
{
    /**
     * The event dispatcher instance.
     *
     * @var \Illuminate\Contracts\Events\Dispatcher
     */
    private $events;
    /**
     * {@inheritdoc}
     */
     
     /**
     * Create a new repository instance.
     *
     * @param  \MoeenBasra\LaravelPassportMongoDB\TokenRepository  $tokenRepository
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     */
    public function __construct(TokenRepository $tokenRepository, Dispatcher $events)
    {
        $this->events = $events;
        $this->tokenRepository = $tokenRepository;
    }
    /**
     * {@inheritdoc}
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity)
    {
        $this->tokenRepository->create([
            '_id' => $accessTokenEntity->getIdentifier(),
            'id' => $accessTokenEntity->getIdentifier(),
            'user_id' => $accessTokenEntity->getUserIdentifier(),
            'client_id' => $accessTokenEntity->getClient()->getIdentifier(),
            'scopes' => $this->scopesToArray($accessTokenEntity->getScopes()),
            'revoked' => false,
            'created_at' => new DateTime,
            'updated_at' => new DateTime,
            'expires_at' => $accessTokenEntity->getExpiryDateTime(),
        ]);

        $this->events->dispatch(new AccessTokenCreated(
            $accessTokenEntity->getIdentifier(),
            $accessTokenEntity->getUserIdentifier(),
            $accessTokenEntity->getClient()->getIdentifier()
        ));
    }
}
