<?php

namespace Laravel\Reverb\Protocols\Pusher\Http\Controllers;

use Illuminate\Support\Facades\Validator;
use JsonException;
use Laravel\Reverb\Protocols\Pusher\ConnectionAuthorityControlSignature;
use Laravel\Reverb\Protocols\Pusher\Contracts\ConnectionAuthorityRegistry;
use Laravel\Reverb\ServerProviderManager;
use Laravel\Reverb\Servers\Reverb\Contracts\PubSubProvider;
use Laravel\Reverb\Servers\Reverb\Http\Connection;
use Laravel\Reverb\Servers\Reverb\Http\Response;
use Psr\Http\Message\RequestInterface;
use React\Promise\PromiseInterface;
use Symfony\Component\HttpKernel\Exception\HttpException;

final class ConnectionLeaseController extends Controller
{
    public function __invoke(
        RequestInterface $request,
        Connection $connection,
        string $appId,
    ): Response|PromiseInterface {
        $this->verify($request, $connection, $appId);
        if (! $this->application->requiresConnectionAuthority()) {
            throw new HttpException(404, 'Not found.');
        }
        try {
            $payload = json_decode($this->body, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return new Response((object) [], 422);
        }
        if (! is_array($payload)
            || count($payload) !== 4
            || array_diff(array_keys($payload), ['principal', 'authority', 'revision', 'expires_at']) !== []
            || ! is_string($payload['principal'] ?? null)
            || ! is_string($payload['authority'] ?? null)
            || ! is_int($payload['revision'] ?? null)
            || ! is_int($payload['expires_at'] ?? null)) {
            return new Response((object) [], 422);
        }
        $validator = Validator::make($payload, [
            'principal' => ['required', 'string', 'regex:/^[A-Za-z0-9_-]{32,128}$/'],
            'authority' => ['required', 'string', 'regex:/^[A-Za-z0-9_-]{32,128}$/'],
            'revision' => ['required', 'integer', 'min:1'],
            'expires_at' => ['required', 'integer', 'min:1'],
        ]);
        if ($validator->fails() || $payload['expires_at'] > time() + 86400) {
            return new Response((object) [], 422);
        }

        if (app(ServerProviderManager::class)->subscribesToEvents()) {
            return app(PubSubProvider::class)->publish([
                'type' => 'authority_lease',
                'application' => serialize($this->application),
                'payload' => $payload,
                'control_signature' => ConnectionAuthorityControlSignature::sign(
                    $this->application,
                    'authority_lease',
                    $payload,
                ),
            ])->then(fn () => new Response((object) []));
        }
        $updated = app(ConnectionAuthorityRegistry::class)->updateLease(
            $this->application,
            $payload['principal'],
            $payload['authority'],
            $payload['revision'],
            $payload['expires_at'],
        );

        return new Response(['connections_updated' => $updated]);
    }
}
