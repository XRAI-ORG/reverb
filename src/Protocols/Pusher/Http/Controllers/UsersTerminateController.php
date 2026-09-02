<?php

namespace Laravel\Reverb\Protocols\Pusher\Http\Controllers;

use Laravel\Reverb\Protocols\Pusher\ConnectionAuthorityControlSignature;
use Laravel\Reverb\Protocols\Pusher\Contracts\ConnectionAuthorityRegistry;
use Laravel\Reverb\ServerProviderManager;
use Laravel\Reverb\Servers\Reverb\Contracts\PubSubProvider;
use Laravel\Reverb\Servers\Reverb\Http\Connection;
use Laravel\Reverb\Servers\Reverb\Http\Response;
use Psr\Http\Message\RequestInterface;
use React\Promise\PromiseInterface;
use Symfony\Component\HttpKernel\Exception\HttpException;

class UsersTerminateController extends Controller
{
    /**
     * Handle the request.
     */
    public function __invoke(RequestInterface $request, Connection $connection, string $appId, string $userId): Response|PromiseInterface
    {
        $this->verify($request, $connection, $appId);
        if ($this->application->requiresConnectionAuthority()
            && preg_match('/^[A-Za-z0-9_-]{32,128}$/D', $userId) !== 1) {
            throw new HttpException(422, 'Invalid connection principal.');
        }

        if (app(ServerProviderManager::class)->subscribesToEvents()) {
            $payload = $this->application->requiresConnectionAuthority()
                ? ['principal' => $userId]
                : ['user_id' => $userId];
            $event = [
                'type' => 'terminate',
                'application' => serialize($this->application),
                'payload' => $payload,
            ];
            if ($this->application->requiresConnectionAuthority()) {
                $event['control_signature'] = ConnectionAuthorityControlSignature::sign(
                    $this->application,
                    'terminate',
                    $payload,
                );
            }

            return app(PubSubProvider::class)->publish($event)
                ->then(fn () => new Response((object) []));
        }

        if ($this->application->requiresConnectionAuthority()) {
            app(ConnectionAuthorityRegistry::class)->terminate($this->application, $userId);
        } else {
            collect($this->channels->connections())
                ->each(function ($connection) use ($userId): void {
                    if ((string) $connection->data('user_id') === $userId) {
                        $connection->disconnect();
                    }
                });
        }

        return new Response((object) []);
    }
}
