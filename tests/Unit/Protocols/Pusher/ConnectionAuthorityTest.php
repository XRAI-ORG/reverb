<?php

use Illuminate\Support\Collection;
use Laravel\Reverb\Application;
use Laravel\Reverb\Contracts\ApplicationProvider;
use Laravel\Reverb\Protocols\Pusher\ConnectionAuthorityControlSignature;
use Laravel\Reverb\Protocols\Pusher\Contracts\ConnectionAuthorityRegistry;
use Laravel\Reverb\Protocols\Pusher\PusherPubSubIncomingMessageHandler;
use Laravel\Reverb\Protocols\Pusher\Server;
use Laravel\Reverb\Tests\FakeConnection;
use React\EventLoop\Loop;

beforeEach(function () {
    $this->authorityApplication = new Application(
        'authority-app',
        'authority-key',
        'authority-secret',
        60,
        30,
        ['*'],
        10_000,
        options: [
            'xrai_connection_authority' => true,
            'allowed_client_events' => ['client-typing'],
        ],
    );
    $application = $this->authorityApplication;
    $provider = Mockery::mock(ApplicationProvider::class);
    $provider->shouldReceive('findByKey')->andReturn($application);
    $provider->shouldReceive('findById')->andReturn($application);
    $provider->shouldReceive('all')->andReturn(new Collection([$application]));
    $this->app->instance(ApplicationProvider::class, $provider);
    $this->server = $this->app->make(Server::class);
});

function authorityUserData(
    string $principal = 'principal_abcdefghijklmnopqrstuvwxyz012345',
    string $generation = 'authority_abcdefghijklmnopqrstuvwxyz012345',
    int $revision = 1,
    ?int $expiresAt = null,
): string {
    return json_encode([
        'id' => $principal,
        'xrai_reverb' => [
            'version' => 1,
            'authority' => $generation,
            'revision' => $revision,
            'expires_at' => $expiresAt ?? time() + 300,
        ],
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
}

function authoritySignin(FakeConnection $connection, string $userData): string
{
    return json_encode([
        'event' => 'pusher:signin',
        'data' => [
            'auth' => 'authority-key:'.hash_hmac(
                'sha256',
                $connection->id().'::user::'.$userData,
                'authority-secret',
            ),
            'user_data' => $userData,
        ],
    ], JSON_THROW_ON_ERROR);
}

it('authenticates one immutable opaque connection authority before protected subscriptions', function () {
    $connection = new FakeConnection;
    $this->server->open($connection);
    $this->server->message($connection, json_encode([
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'private-records', 'auth' => 'invalid'],
    ], JSON_THROW_ON_ERROR));
    $connection->assertReceived([
        'event' => 'pusher:error',
        'data' => json_encode(['code' => 4009, 'message' => 'Connection is unauthorized']),
    ]);

    $userData = authorityUserData();
    $this->server->message($connection, authoritySignin($connection, $userData));
    $connection->assertReceived([
        'event' => 'pusher:signin_success',
        'data' => json_encode(['user_data' => $userData]),
    ]);

    $privateAuth = 'authority-key:'.hash_hmac(
        'sha256',
        $connection->id().':private-records',
        'authority-secret',
    );
    $this->server->message($connection, json_encode([
        'event' => 'pusher:subscribe',
        'data' => ['channel' => 'private-records', 'auth' => $privateAuth],
    ], JSON_THROW_ON_ERROR));
    $connection->assertReceived([
        'event' => 'pusher_internal:subscription_succeeded',
        'data' => '{}',
        'channel' => 'private-records',
    ]);

    $this->server->message($connection, authoritySignin($connection, $userData));
    expect(app(ConnectionAuthorityRegistry::class)->authority($connection)?->revision)->toBe(1);

    $replacement = authorityUserData(generation: 'authority_replacement_abcdefghijklmnopqrstu');
    $this->server->message($connection, authoritySignin($connection, $replacement));
    $connection->assertReceived([
        'event' => 'pusher:error',
        'data' => json_encode(['code' => 4009, 'message' => 'Connection is unauthorized']),
    ]);
});

it('rejects malformed signed lease data and guessed server user channels', function () {
    $connection = new FakeConnection;
    $this->server->open($connection);
    $malformed = json_encode([
        'id' => 'principal_abcdefghijklmnopqrstuvwxyz012345',
        'xrai_reverb' => [
            'version' => 1,
            'authority' => 'authority_abcdefghijklmnopqrstuvwxyz012345',
            'revision' => 1,
            'expires_at' => time() + 300,
            'unknown' => true,
        ],
    ], JSON_THROW_ON_ERROR);
    $this->server->message($connection, authoritySignin($connection, $malformed));
    $connection->assertReceived([
        'event' => 'pusher:error',
        'data' => json_encode(['code' => 4009, 'message' => 'Connection is unauthorized']),
    ]);

    $scalarWatchlist = json_encode([
        'id' => 'principal_abcdefghijklmnopqrstuvwxyz012345',
        'watchlist' => 'not-a-list',
        'xrai_reverb' => [
            'version' => 1,
            'authority' => 'authority_abcdefghijklmnopqrstuvwxyz012345',
            'revision' => 1,
            'expires_at' => time() + 300,
        ],
    ], JSON_THROW_ON_ERROR);
    $this->server->message($connection, authoritySignin($connection, $scalarWatchlist));
    $connection->assertReceived([
        'event' => 'pusher:error',
        'data' => json_encode(['code' => 4009, 'message' => 'Connection is unauthorized']),
    ]);

    $userData = authorityUserData();
    $this->server->message($connection, authoritySignin($connection, $userData));
    $this->server->message($connection, json_encode([
        'event' => 'pusher:subscribe',
        'data' => ['channel' => '#server-to-user-guessed_principal_abcdefghijklmnopqrstuv'],
    ], JSON_THROW_ON_ERROR));
    $connection->assertReceived([
        'event' => 'pusher:error',
        'data' => json_encode(['code' => 4009, 'message' => 'Connection is unauthorized']),
    ]);
});

it('applies only newer matching leases and terminates at an earlier deadline', function () {
    $connection = new FakeConnection;
    $this->server->open($connection);
    $principal = 'principal_abcdefghijklmnopqrstuvwxyz012345';
    $generation = 'authority_abcdefghijklmnopqrstuvwxyz012345';
    $this->server->message($connection, authoritySignin(
        $connection,
        authorityUserData($principal, $generation),
    ));
    $registry = app(ConnectionAuthorityRegistry::class);

    expect($registry->updateLease(
        $this->authorityApplication,
        $principal,
        'authority_wrong_abcdefghijklmnopqrstuvwxyz',
        2,
        time() + 600,
    ))->toBe(0)
        ->and($registry->updateLease(
            $this->authorityApplication,
            $principal,
            $generation,
            1,
            time() + 600,
        ))->toBe(0)
        ->and($registry->updateLease(
            $this->authorityApplication,
            $principal,
            $generation,
            2,
            time(),
        ))->toBe(1);
    $connection->assertHasBeenTerminated();
    expect($registry->authority($connection))->toBeNull()
        ->and($registry->updateLease(
            $this->authorityApplication,
            $principal,
            $generation,
            3,
            time() + 600,
        ))->toBe(0);
});

it('allows only configured member client events and replaces browser supplied sender data', function () {
    $sender = new FakeConnection('authority-sender');
    $recipient = new FakeConnection('authority-recipient');
    foreach ([$sender, $recipient] as $connection) {
        $this->server->open($connection);
        $this->server->message($connection, authoritySignin(
            $connection,
            authorityUserData(
                principal: 'principal_'.substr(hash('sha256', $connection->id()), 0, 40),
            ),
        ));
    }

    $channel = 'presence-conversation';
    $subscribe = function (FakeConnection $connection, string $publicId, string $name) use ($channel): void {
        $data = json_encode([
            'user_id' => $publicId,
            'user_info' => ['publicId' => $publicId, 'name' => $name],
        ], JSON_THROW_ON_ERROR);
        $auth = 'authority-key:'.hash_hmac(
            'sha256',
            $connection->id().':'.$channel.':'.$data,
            'authority-secret',
        );
        $this->server->message($connection, json_encode([
            'event' => 'pusher:subscribe',
            'data' => ['channel' => $channel, 'auth' => $auth, 'channel_data' => $data],
        ], JSON_THROW_ON_ERROR));
    };
    $subscribe($sender, '2dc10b6b-b6c2-48b2-8f89-977b1c74808d', 'Sender');
    $subscribe($recipient, 'a6c4f81a-9fd5-4fad-af6b-04987a1df720', 'Recipient');

    $this->server->message($sender, json_encode([
        'event' => 'client-typing',
        'channel' => $channel,
        'data' => [
            'active' => true,
            'pusher_sender' => ['id' => 'forged'],
        ],
    ], JSON_THROW_ON_ERROR));
    $recipient->assertReceived([
        'event' => 'client-typing',
        'channel' => $channel,
        'data' => [
            'active' => true,
            'pusher_sender' => [
                'id' => '2dc10b6b-b6c2-48b2-8f89-977b1c74808d',
                'info' => [
                    'publicId' => '2dc10b6b-b6c2-48b2-8f89-977b1c74808d',
                    'name' => 'Sender',
                ],
            ],
        ],
        'user_id' => '2dc10b6b-b6c2-48b2-8f89-977b1c74808d',
    ]);

    $this->server->message($sender, json_encode([
        'event' => 'client-not-approved',
        'channel' => $channel,
        'data' => [],
    ], JSON_THROW_ON_ERROR));
    $sender->assertReceived([
        'event' => 'pusher:error',
        'data' => json_encode([
            'code' => 4301,
            'message' => 'The app does not allow this client event.',
        ]),
    ]);
});

it('accepts only signed scaled lease controls for the matching application', function () {
    $connection = new FakeConnection;
    $this->server->open($connection);
    $principal = 'principal_abcdefghijklmnopqrstuvwxyz012345';
    $generation = 'authority_abcdefghijklmnopqrstuvwxyz012345';
    $this->server->message($connection, authoritySignin(
        $connection,
        authorityUserData($principal, $generation),
    ));
    $payload = [
        'principal' => $principal,
        'authority' => $generation,
        'revision' => 2,
        'expires_at' => time() + 600,
    ];
    $handler = new PusherPubSubIncomingMessageHandler;
    $handler->handle(json_encode([
        'type' => 'authority_lease',
        'application' => serialize($this->authorityApplication),
        'payload' => $payload,
        'control_signature' => str_repeat('0', 64),
    ], JSON_THROW_ON_ERROR));
    expect(app(ConnectionAuthorityRegistry::class)->authority($connection)?->revision)
        ->toBe(1);

    $forgedApplication = new Application(
        $this->authorityApplication->id(),
        'forged-key',
        'forged-secret',
        60,
        30,
        ['*'],
        10_000,
        options: ['xrai_connection_authority' => true],
    );
    $handler->handle(json_encode([
        'type' => 'authority_lease',
        'application' => serialize($forgedApplication),
        'payload' => $payload,
        'control_signature' => ConnectionAuthorityControlSignature::sign(
            $forgedApplication,
            'authority_lease',
            $payload,
        ),
    ], JSON_THROW_ON_ERROR));
    expect(app(ConnectionAuthorityRegistry::class)->authority($connection)?->revision)
        ->toBe(1);

    $handler->handle(json_encode([
        'type' => 'authority_lease',
        'application' => serialize($this->authorityApplication),
        'payload' => $payload,
        'control_signature' => ConnectionAuthorityControlSignature::sign(
            $this->authorityApplication,
            'authority_lease',
            $payload,
        ),
    ], JSON_THROW_ON_ERROR));
    expect(app(ConnectionAuthorityRegistry::class)->authority($connection)?->revision)
        ->toBe(2);
});

it('reschedules local expiry after a signed scaled lease update', function () {
    $connection = new FakeConnection;
    $this->server->open($connection);
    $principal = 'principal_abcdefghijklmnopqrstuvwxyz012345';
    $generation = 'authority_abcdefghijklmnopqrstuvwxyz012345';
    $this->server->message($connection, authoritySignin(
        $connection,
        authorityUserData($principal, $generation),
    ));
    $payload = [
        'principal' => $principal,
        'authority' => $generation,
        'revision' => 2,
        'expires_at' => time() + 1,
    ];

    (new PusherPubSubIncomingMessageHandler)->handle(json_encode([
        'type' => 'authority_lease',
        'application' => serialize($this->authorityApplication),
        'payload' => $payload,
        'control_signature' => ConnectionAuthorityControlSignature::sign(
            $this->authorityApplication,
            'authority_lease',
            $payload,
        ),
    ], JSON_THROW_ON_ERROR));
    Loop::addTimer(1.25, static fn () => Loop::stop());
    Loop::run();

    $connection->assertHasBeenTerminated();
});
