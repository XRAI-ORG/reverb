<?php

use Laravel\Reverb\ConfigApplicationProvider;
use Laravel\Reverb\Contracts\ApplicationProvider;
use Laravel\Reverb\Protocols\Pusher\Channels\ChannelConnection;
use Laravel\Reverb\Protocols\Pusher\Contracts\ConnectionAuthorityRegistry;
use Laravel\Reverb\Tests\ReverbTestCase;
use Laravel\Reverb\Tests\TestConnection;
use React\Http\Message\ResponseException;
use React\Promise\Deferred;

use function React\Async\await;
use function React\Promise\Timer\timeout;

uses(ReverbTestCase::class);

function enableConnectionAuthorityApplication(): void
{
    config()->set('reverb.apps.apps.0.options.xrai_connection_authority', true);
    config()->set('reverb.apps.apps.0.allowed_client_events', ['client-typing']);
    app()->instance(
        ApplicationProvider::class,
        new ConfigApplicationProvider(collect(config('reverb.apps.apps'))),
    );
}

/** @return array{TestConnection, string, string} */
function signInConnectionAuthority(
    string $principal = 'principal_abcdefghijklmnopqrstuvwxyz012345',
    string $generation = 'authority_abcdefghijklmnopqrstuvwxyz012345',
): array {
    $connection = connect();
    $userData = json_encode([
        'id' => $principal,
        'xrai_reverb' => [
            'version' => 1,
            'authority' => $generation,
            'revision' => 1,
            'expires_at' => time() + 300,
        ],
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $response = send([
        'event' => 'pusher:signin',
        'data' => [
            'auth' => 'reverb-key:'.hash_hmac(
                'sha256',
                $connection->socketId().'::user::'.$userData,
                'reverb-secret',
            ),
            'user_data' => $userData,
        ],
    ], $connection);
    expect($response)->toContain('pusher:signin_success');

    return [$connection, $principal, $generation];
}

it('does not expose the fork lease endpoint for a stock application', function () {
    await($this->signedPostRequest('xrai/connection-leases', [
        'principal' => 'principal_abcdefghijklmnopqrstuvwxyz012345',
        'authority' => 'authority_abcdefghijklmnopqrstuvwxyz012345',
        'revision' => 2,
        'expires_at' => time() + 300,
    ]));
})->throws(ResponseException::class, exceptionCode: 404);

it('updates a signed connection lease through the public server API', function () {
    enableConnectionAuthorityApplication();
    [$connection, $principal, $generation] = signInConnectionAuthority();
    subscribe('private-records', connection: $connection);

    $response = await($this->signedPostRequest('xrai/connection-leases', [
        'principal' => $principal,
        'authority' => $generation,
        'revision' => 2,
        'expires_at' => time() + 600,
    ]));

    $registered = channels()->find('private-records')?->findById($connection->socketId());
    expect($registered)->toBeInstanceOf(ChannelConnection::class);
    if (! $registered instanceof ChannelConnection) {
        throw new LogicException('The protected subscription was not registered.');
    }
    expect($response->getStatusCode())->toBe(200)
        ->and($response->getBody()->getContents())->toBe('{"connections_updated":1}')
        ->and(app(ConnectionAuthorityRegistry::class)
            ->authority($registered->connection())?->revision)->toBe(2);
});

it('reports when a lease update matches no live connection', function () {
    enableConnectionAuthorityApplication();

    $response = await($this->signedPostRequest('xrai/connection-leases', [
        'principal' => 'principal_abcdefghijklmnopqrstuvwxyz012345',
        'authority' => 'authority_abcdefghijklmnopqrstuvwxyz012345',
        'revision' => 2,
        'expires_at' => time() + 600,
    ]));

    expect($response->getStatusCode())->toBe(200)
        ->and($response->getBody()->getContents())->toBe('{"connections_updated":0}');
});

it('closes a live connection at a shortened lease deadline', function () {
    enableConnectionAuthorityApplication();
    [$connection, $principal, $generation] = signInConnectionAuthority();
    $closed = new Deferred;
    $connection->connection->on('close', static fn () => $closed->resolve(true));

    await($this->signedPostRequest('xrai/connection-leases', [
        'principal' => $principal,
        'authority' => $generation,
        'revision' => 2,
        'expires_at' => time() + 1,
    ]));

    expect(await(timeout($closed->promise(), 2)))->toBeTrue();
});

it('rejects malformed lease data and an invalid server signature', function () {
    enableConnectionAuthorityApplication();

    await($this->signedPostRequest('xrai/connection-leases', [
        'principal' => 'short',
        'authority' => 'authority_abcdefghijklmnopqrstuvwxyz012345',
        'revision' => 0,
        'expires_at' => time() + 90_000,
    ]));
})->throws(ResponseException::class, exceptionCode: 422);

it('rejects an unsigned lease command', function () {
    enableConnectionAuthorityApplication();

    await($this->postRequest('xrai/connection-leases', [
        'principal' => 'principal_abcdefghijklmnopqrstuvwxyz012345',
        'authority' => 'authority_abcdefghijklmnopqrstuvwxyz012345',
        'revision' => 2,
        'expires_at' => time() + 300,
    ]));
})->throws(ResponseException::class, exceptionCode: 401);
