<?php

namespace Laravel\Reverb\Protocols\Pusher;

use Laravel\Reverb\Application;
use Laravel\Reverb\Contracts\ApplicationProvider;
use Laravel\Reverb\Exceptions\InvalidApplication;
use Laravel\Reverb\Protocols\Pusher\Contracts\ChannelManager;
use Laravel\Reverb\Protocols\Pusher\Contracts\ConnectionAuthorityRegistry;
use Laravel\Reverb\Servers\Reverb\Contracts\PubSubIncomingMessageHandler;

class PusherPubSubIncomingMessageHandler implements PubSubIncomingMessageHandler
{
    protected array $events = [];

    /**
     * Handle an incoming message from the PubSub provider.
     */
    public function handle(string $payload): void
    {
        $event = json_decode($payload, associative: true, flags: JSON_THROW_ON_ERROR);

        $this->processEventListeners($event);

        $type = $event['type'] ?? null;
        if (! is_string($type)) {
            return;
        }
        if ($type === 'metrics') {
            $metric = is_string($event['payload'] ?? null)
                ? unserialize($event['payload'], ['allowed_classes' => [
                    Application::class, PendingMetric::class, MetricType::class,
                ]])
                : null;
            if ($metric instanceof PendingMetric) {
                app(MetricsHandler::class)->publish($metric);
            }

            return;
        }
        $publishedApplication = unserialize($event['application'] ?? null, ['allowed_classes' => [Application::class]]);
        if (! $publishedApplication instanceof Application) {
            return;
        }
        try {
            $application = app(ApplicationProvider::class)->findById($publishedApplication->id());
        } catch (InvalidApplication) {
            return;
        }
        if (($type === 'authority_lease'
                || ($type === 'terminate' && $application->requiresConnectionAuthority()))
            && (! is_array($event['payload'] ?? null)
                || ! ConnectionAuthorityControlSignature::valid(
                    $application,
                    $type,
                    $event['payload'],
                    $event['control_signature'] ?? null,
                ))) {
            return;
        }

        $except = isset($event['socket_id']) ?
            app(ChannelManager::class)->for($application)->findConnection($event['socket_id'])
            : null;

        match ($type) {
            'message' => EventDispatcher::dispatchSynchronously(
                $application,
                $event['payload'],
                $except?->connection()
            ),
            'terminate' => $this->terminate($application, $event['payload'] ?? null),
            'authority_lease' => $this->updateLease($application, $event['payload'] ?? null),
            default => null,
        };
    }

    private function terminate(Application $application, mixed $payload): void
    {
        if (! $application->requiresConnectionAuthority()) {
            if (! is_array($payload) || ! is_scalar($payload['user_id'] ?? null)) {
                return;
            }
            collect(app(ChannelManager::class)->for($application)->connections())
                ->each(function ($connection) use ($payload): void {
                    if ((string) $connection->data('user_id') === (string) $payload['user_id']) {
                        $connection->disconnect();
                    }
                });

            return;
        }
        if (! is_array($payload)
            || array_keys($payload) !== ['principal']
            || ! is_string($payload['principal'])) {
            return;
        }
        app(ConnectionAuthorityRegistry::class)->terminate($application, $payload['principal']);
    }

    private function updateLease(Application $application, mixed $payload): void
    {
        if (! is_array($payload)
            || array_keys($payload) !== ['principal', 'authority', 'revision', 'expires_at']
            || ! is_string($payload['principal'])
            || ! is_string($payload['authority'])
            || ! is_int($payload['revision'])
            || ! is_int($payload['expires_at'])) {
            return;
        }
        app(ConnectionAuthorityRegistry::class)->updateLease(
            $application,
            $payload['principal'],
            $payload['authority'],
            $payload['revision'],
            $payload['expires_at'],
        );
    }

    /**
     * Process the given event.
     */
    protected function processEventListeners(array $event): void
    {
        foreach ($this->events as $eventName => $listeners) {
            if (($event['type'] ?? null) === $eventName) {
                foreach ($listeners as $listener) {
                    $listener($event);
                }
            }
        }
    }

    /**
     * Listen for the given event.
     */
    public function listen(string $event, callable $callback): void
    {
        $this->events[$event][] = $callback;
    }

    /**
     * Stop listening for the given event.
     */
    public function stopListening(string $event): void
    {
        unset($this->events[$event]);
    }
}
