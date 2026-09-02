<?php

namespace Laravel\Reverb\Protocols\Pusher;

use Exception;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use InvalidArgumentException;
use JsonException;
use Laravel\Reverb\Contracts\Connection;
use Laravel\Reverb\Protocols\Pusher\Channels\CacheChannel;
use Laravel\Reverb\Protocols\Pusher\Channels\Channel;
use Laravel\Reverb\Protocols\Pusher\Contracts\ChannelManager;
use Laravel\Reverb\Protocols\Pusher\Contracts\ConnectionAuthorityRegistry;
use Laravel\Reverb\Protocols\Pusher\Exceptions\ConnectionUnauthorized;

class EventHandler
{
    protected ConnectionAuthorityRegistry $connectionAuthorities;

    /**
     * Create a new Pusher event instance.
     */
    public function __construct(
        protected ChannelManager $channels,
        ?ConnectionAuthorityRegistry $connectionAuthorities = null,
    ) {
        $this->connectionAuthorities = $connectionAuthorities
            ?? app(ConnectionAuthorityRegistry::class);
    }

    /**
     * Handle an incoming Pusher event.
     */
    public function handle(Connection $connection, string $event, array $payload = []): void
    {
        $event = Str::after($event, 'pusher:');

        match ($event) {
            'connection_established' => $this->acknowledge($connection),
            'signin' => $this->signin(
                $connection,
                $payload['auth'] ?? null,
                $payload['user_data'] ?? null,
            ),
            'subscribe' => $this->subscribe(
                $connection,
                $payload['channel'],
                $payload['auth'] ?? null,
                $payload['channel_data'] ?? null
            ),
            'unsubscribe' => $this->unsubscribe($connection, $payload['channel']),
            'ping' => $this->pong($connection),
            'pong' => $connection->touch(),
            default => throw new Exception('Unknown Pusher event: '.$event),
        };
    }

    /**
     * Acknowledge the connection.
     */
    public function acknowledge(Connection $connection): void
    {
        $this->send($connection, 'connection_established', [
            'socket_id' => $connection->id(),
            'activity_timeout' => $connection->app()->activityTimeout(),
        ]);
    }

    /**
     * Subscribe to the given channel.
     */
    public function subscribe(Connection $connection, string $channel, ?string $auth = null, ?string $data = null): void
    {
        Validator::make([
            'channel' => $channel,
            'auth' => $auth,
            'channel_data' => $data,
        ], [
            'channel' => ['nullable', 'string'],
            'auth' => ['nullable', 'string'],
            'channel_data' => ['nullable', 'json'],
        ])->validate();

        if ($connection->app()->requiresConnectionAuthority() && $this->protectedChannel($channel)) {
            $authority = $this->connectionAuthorities->authority($connection);
            if (! $authority instanceof ConnectionAuthority
                || (str_starts_with($channel, '#server-to-user-')
                    && ! hash_equals('#server-to-user-'.$authority->principal, $channel))) {
                throw new ConnectionUnauthorized;
            }
        }

        $channel = $this->channels
            ->for($connection->app())
            ->findOrCreate($channel);

        $channel->subscribe($connection, $auth, $data);

        $this->afterSubscribe($channel, $connection);
    }

    public function signin(Connection $connection, mixed $auth, mixed $userData): void
    {
        if (! is_string($auth) || ! is_string($userData)) {
            throw new ConnectionUnauthorized;
        }
        $parts = explode(':', $auth, 2);
        if (count($parts) !== 2 || ! hash_equals($connection->app()->key(), $parts[0])) {
            throw new ConnectionUnauthorized;
        }
        $expected = hash_hmac(
            'sha256',
            $connection->id().'::user::'.$userData,
            $connection->app()->secret(),
        );
        if (! hash_equals($expected, $parts[1])) {
            throw new ConnectionUnauthorized;
        }
        try {
            $authority = ConnectionAuthority::fromUserData($userData);
            $authority = $this->connectionAuthorities->authenticate($connection, $authority);
        } catch (InvalidArgumentException|JsonException) {
            throw new ConnectionUnauthorized;
        }

        $this->send($connection, 'signin_success', [
            'user_data' => $authority->normalizedUserData,
        ]);
    }

    private function protectedChannel(string $channel): bool
    {
        return Str::startsWith($channel, [
            'private-',
            'presence-',
            '#server-to-user-',
        ]);
    }

    /**
     * Carry out any actions that should be performed after a subscription.
     */
    protected function afterSubscribe(Channel $channel, Connection $connection): void
    {
        if ($connection->app()->requiresConnectionAuthority()
            && $channel->isProtected()
            && ! $this->connectionAuthorities->permitsProtectedTraffic($connection)) {
            $channel->unsubscribe($connection);
            throw new ConnectionUnauthorized;
        }
        $this->sendInternally($connection, 'subscription_succeeded', $channel->data(), $channel->name());

        match (true) {
            $channel instanceof CacheChannel => $this->sendCachedPayload($channel, $connection),
            default => null,
        };
    }

    /**
     * Unsubscribe from the given channel.
     */
    public function unsubscribe(Connection $connection, string $channel): void
    {
        $channel = $this->channels
            ->for($connection->app())
            ->find($channel)
            ?->unsubscribe($connection);
    }

    /**
     * Send the cached payload for the given channel.
     */
    protected function sendCachedPayload(CacheChannel $channel, Connection $connection): void
    {
        if ($channel->hasCachedPayload()) {
            $connection->send(
                json_encode($channel->cachedPayload())
            );

            return;
        }

        $this->send($connection, 'cache_miss', channel: $channel->name());
    }

    /**
     * Respond to a ping on the given connection.
     */
    public function pong(Connection $connection): void
    {
        static::send($connection, 'pong');
    }

    /**
     * Send a ping to the given connection.
     */
    public function ping(Connection $connection): void
    {
        $connection->usesControlFrames()
            ? $connection->control()
            : static::send($connection, 'ping');

        $connection->ping();
    }

    /**
     * Send a response to the given connection.
     */
    public function send(Connection $connection, string $event, array $data = [], ?string $channel = null): void
    {
        $connection->send(
            static::formatPayload($event, $data, $channel)
        );
    }

    /**
     * Send an internal response to the given connection.
     */
    public function sendInternally(Connection $connection, string $event, array $data = [], ?string $channel = null): void
    {
        $connection->send(
            static::formatInternalPayload($event, $data, $channel)
        );
    }

    /**
     * Format the payload for the given event.
     */
    public function formatPayload(string $event, array $data = [], ?string $channel = null, string $prefix = 'pusher:'): string|false
    {
        return json_encode(
            array_filter([
                'event' => $prefix.$event,
                'data' => empty($data) ? null : json_encode($data),
                'channel' => $channel,
            ])
        );
    }

    /**
     * Format the internal payload for the given event.
     */
    public function formatInternalPayload(string $event, array $data = [], $channel = null): string|false
    {
        return json_encode(
            array_filter([
                'event' => 'pusher_internal:'.$event,
                'data' => json_encode((object) $data),
                'channel' => $channel,
            ])
        );
    }
}
