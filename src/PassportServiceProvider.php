<?php

namespace Kayrules\LumenPassport;

use Kayrules\LumenPassport\Console\Commands\Purge;
use Illuminate\Support\ServiceProvider;
use Illuminate\Database\Connection;

use DateInterval;
use Illuminate\Auth\RequestGuard;
use Illuminate\Auth\Events\Logout;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Request;
use MoeenBasra\LaravelPassportMongoDB\Guards\TokenGuard;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\ResourceServer;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\ImplicitGrant;
use League\OAuth2\Server\Grant\PasswordGrant;
use MoeenBasra\LaravelPassportMongoDB\Bridge\PersonalAccessGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use MoeenBasra\LaravelPassportMongoDB\Bridge\RefreshTokenRepository;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use MoeenBasra\LaravelPassportMongoDB\Passport;


/**
 * Class CustomQueueServiceProvider
 * @package App\Providers
 */
class PassportServiceProvider extends \MoeenBasra\LaravelPassportMongoDB\PassportServiceProvider
{

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
		$this->app->configure('api');
		$this->app->register(\MoeenBasra\LaravelPassportMongoDB\PassportServiceProvider::class);

        $this->app->singleton(Connection::class, function() {
            return $this->app['db.connection'];
        });

        if ($this->app->runningInConsole()) {
            $this->commands([
                Purge::class
            ]);
        }

        $this->registerRoutes();
        $this->registerAuthorizationServer();

        $this->registerResourceServer();
    }
    /**
     * @return void
     */
    public function register()
    {
    }

    /**
     * Register routes for transient tokens, clients, and personal access tokens.
     *
     * @return void
     */
    public function registerRoutes()
    {
        $this->forAccessTokens();
        $this->forTransientTokens();
        $this->forClients();
        $this->forPersonalAccessTokens();
    }

    /**
     * Register the routes for retrieving and issuing access tokens.
     *
     * @return void
     */
    public function forAccessTokens()
    {
		$this->app->group(['prefix' => config('api.prefix')], function () {
			$this->app->post('/oauth/token', [
	            'uses' => '\Kayrules\LumenPassport\Http\Controllers\AccessTokenController@issueToken'
	        ]);
		});

        $this->app->group(['prefix' => config('api.prefix'), 'middleware' => ['auth']], function () {
            $this->app->get('/oauth/tokens', [
                'uses' => '\MoeenBasra\LaravelPassportMongoDB\Http\Controllers\AuthorizedAccessTokenController@forUser',
            ]);

            $this->app->delete('/oauth/tokens/{token_id}', [
                'uses' => '\MoeenBasra\LaravelPassportMongoDB\Http\Controllers\AuthorizedAccessTokenController@destroy',
            ]);
        });
    }

    /**
     * Register the routes needed for refreshing transient tokens.
     *
     * @return void
     */
    public function forTransientTokens()
    {
		$this->app->group(['prefix' => config('api.prefix')], function () {
	        $this->app->post('/oauth/token/refresh', [
	            'middleware' => ['auth'],
	            'uses' => '\MoeenBasra\LaravelPassportMongoDB\Http\Controllers\TransientTokenController@refresh',
	        ]);
		});
    }

    /**
     * Register the routes needed for managing clients.
     *
     * @return void
     */
    public function forClients()
    {
        $this->app->group(['prefix' => config('api.prefix'), 'middleware' => ['auth']], function () {
            $this->app->get('/oauth/clients', [
                'uses' => '\MoeenBasra\LaravelPassportMongoDB\Http\Controllers\ClientController@forUser',
            ]);

            $this->app->post('/oauth/clients', [
                'uses' => '\MoeenBasra\LaravelPassportMongoDB\Http\Controllers\ClientController@store',
            ]);

            $this->app->put('/oauth/clients/{client_id}', [
                'uses' => '\MoeenBasra\LaravelPassportMongoDB\Http\Controllers\ClientController@update',
            ]);

            $this->app->delete('/oauth/clients/{client_id}', [
                'uses' => '\MoeenBasra\LaravelPassportMongoDB\Http\Controllers\ClientController@destroy',
            ]);
        });
    }

    /**
     * Register the routes needed for managing personal access tokens.
     *
     * @return void
     */
    public function forPersonalAccessTokens()
    {
        $this->app->group(['prefix' => config('api.prefix'), 'middleware' => ['auth']], function () {
            $this->app->get('/oauth/scopes', [
                'uses' => '\MoeenBasra\LaravelPassportMongoDB\Http\Controllers\ScopeController@all',
            ]);

            $this->app->get('/oauth/personal-access-tokens', [
                'uses' => '\MoeenBasra\LaravelPassportMongoDB\Http\Controllers\PersonalAccessTokenController@forUser',
            ]);

            $this->app->post('/oauth/personal-access-tokens', [
                'uses' => '\MoeenBasra\LaravelPassportMongoDB\Http\Controllers\PersonalAccessTokenController@store',
            ]);

            $this->app->delete('/oauth/personal-access-tokens/{token_id}', [
                'uses' => '\MoeenBasra\LaravelPassportMongoDB\Http\Controllers\PersonalAccessTokenController@destroy',
            ]);
        });
    }
    
    /**
     * Register the authorization server.
     *
     * @return void
     */
    protected function registerAuthorizationServer()
    {
        $this->app->singleton(AuthorizationServer::class, function () {
            
            return tap($this->makeAuthorizationServer(), function ($server) {
                $server->enableGrantType(
                    $this->makeAuthCodeGrant(), Passport::tokensExpireIn()
                );
                
                $server->enableGrantType(
                    $this->makeRefreshTokenGrant(), Passport::tokensExpireIn()
                );

                $server->enableGrantType(
                    $this->makePasswordGrant(), Passport::tokensExpireIn()
                );

                $server->enableGrantType(
                    new PersonalAccessGrant, new DateInterval('P1Y')
                );

                $server->enableGrantType(
                    new ClientCredentialsGrant, Passport::tokensExpireIn()
                );

                if (Passport::$implicitGrantEnabled) {
                    $server->enableGrantType(
                        $this->makeImplicitGrant(), Passport::tokensExpireIn()
                    );
                }
            });
        });
    }
    
    /**
     * Build the Auth Code grant instance.
     *
     * @return \League\OAuth2\Server\Grant\AuthCodeGrant
     */
    protected function buildAuthCodeGrant()
    {
        return new AuthCodeGrant(
            $this->app->make(\MoeenBasra\LaravelPassportMongoDB\Bridge\AuthCodeRepository::class),
            $this->app->make(Bridge\RefreshTokenRepository::class),
            new DateInterval('PT10M')
        );
    }
    
    /**
     * Create and configure a Refresh Token grant instance.
     *
     * @return \League\OAuth2\Server\Grant\RefreshTokenGrant
     */
    protected function makeRefreshTokenGrant()
    {
        $repository = $this->app->make(Bridge\RefreshTokenRepository::class);
        
        return tap(new RefreshTokenGrant($repository), function ($grant) {
            $grant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());
        });
    }
    
    /**
     * Create and configure a Password grant instance.
     *
     * @return \League\OAuth2\Server\Grant\PasswordGrant
     */
    protected function makePasswordGrant()
    {
        $grant = new PasswordGrant(
            $this->app->make(\MoeenBasra\LaravelPassportMongoDB\Bridge\UserRepository::class),
            $this->app->make(Bridge\RefreshTokenRepository::class)
        );

        $grant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());

        return $grant;
    }
    
    /**
     * Make the authorization service instance.
     *
     * @return \League\OAuth2\Server\AuthorizationServer
     */
    public function makeAuthorizationServer()
    {      
        return new AuthorizationServer(
            $this->app->make(\MoeenBasra\LaravelPassportMongoDB\Bridge\ClientRepository::class),
            $this->app->make(\Kayrules\LumenPassport\Bridge\AccessTokenRepository::class),
            $this->app->make(\MoeenBasra\LaravelPassportMongoDB\Bridge\ScopeRepository::class),
            $this->makeCryptKey('oauth-private.key'),
            app('encrypter')->getKey()
        );
    }
    /**
     * Register the resource server.
     *
     * @return void
     */
    protected function registerResourceServer()
    {   
        $this->app->singleton(\League\OAuth2\Server\ResourceServer::class, function () {
            return new ResourceServer(
                $this->app->make(\Kayrules\LumenPassport\Bridge\AccessTokenRepository::class),
                $this->makeCryptKey('oauth-public.key')
            );
        });
    }   
}
