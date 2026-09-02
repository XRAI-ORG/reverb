<?php

namespace Laravel\Reverb\Protocols\Pusher\Managers;

use InvalidArgumentException;
use Laravel\Reverb\Application;
use Laravel\Reverb\Contracts\Connection;
use Laravel\Reverb\Events\ConnectionAuthorityAuthenticated;
use Laravel\Reverb\Events\ConnectionAuthorityLeaseUpdated;
use Laravel\Reverb\Events\ConnectionAuthorityTerminated;
use Laravel\Reverb\Protocols\Pusher\ConnectionAuthority;
use Laravel\Reverb\Protocols\Pusher\Contracts\ConnectionAuthorityRegistry;
use React\EventLoop\LoopInterface;
use React\EventLoop\TimerInterface;

final class ArrayConnectionAuthorityRegistry implements ConnectionAuthorityRegistry
{
    /** @var array<string, array{connection: Connection, authority: ?ConnectionAuthority, terminal: bool, timer: ?TimerInterface}> */
    private array $connections = [];

    /** @var array<string, array<string, true>> */
    private array $principals = [];

    public function __construct(private readonly LoopInterface $loop) {}

    public function register(Connection $connection): void
    {
        $key = $this->connectionKey($connection);
        $this->remove($connection);
        $this->connections[$key] = [
            'connection' => $connection,
            'authority' => null,
            'terminal' => false,
            'timer' => null,
        ];
    }

    public function authenticate(Connection $connection, ConnectionAuthority $authority): ConnectionAuthority
    {
        $key = $this->connectionKey($connection);
        $state = $this->connections[$key] ?? null;
        if ($state === null || $state['terminal'] || ! $authority->isCurrent()) {
            throw new InvalidArgumentException('Connection authority is unavailable.');
        }
        $current = $state['authority'];
        if ($current instanceof ConnectionAuthority) {
            if (! $current->sameIdentity($authority)
                || $current->revision !== $authority->revision
                || $current->expiresAt !== $authority->expiresAt
                || ! hash_equals($current->normalizedUserData, $authority->normalizedUserData)) {
                throw new InvalidArgumentException('Connection authority is immutable.');
            }

            return $current;
        }
        $this->connections[$key]['authority'] = $authority;
        $principalKey = $this->principalKey($connection->app(), $authority->principal);
        $this->principals[$principalKey][$key] = true;
        $this->scheduleExpiry($key, $authority);
        ConnectionAuthorityAuthenticated::dispatch($connection->app());

        return $authority;
    }

    public function authority(Connection $connection): ?ConnectionAuthority
    {
        $state = $this->connections[$this->connectionKey($connection)] ?? null;
        if ($state === null || $state['terminal']) {
            return null;
        }
        $authority = $state['authority'];
        if ($authority instanceof ConnectionAuthority && ! $authority->isCurrent()) {
            $application = $state['connection']->app();
            $this->terminateConnection($this->connectionKey($connection));
            ConnectionAuthorityTerminated::dispatch($application, 1, 'deadline_expired');

            return null;
        }

        return $authority;
    }

    public function permitsProtectedTraffic(Connection $connection): bool
    {
        return $this->authority($connection)?->isCurrent() === true;
    }

    public function remove(Connection $connection): void
    {
        $key = $this->connectionKey($connection);
        $state = $this->connections[$key] ?? null;
        if ($state === null) {
            return;
        }
        if ($state['timer'] instanceof TimerInterface) {
            $this->loop->cancelTimer($state['timer']);
        }
        $authority = $state['authority'];
        if ($authority instanceof ConnectionAuthority) {
            $principalKey = $this->principalKey($connection->app(), $authority->principal);
            unset($this->principals[$principalKey][$key]);
            if (($this->principals[$principalKey] ?? []) === []) {
                unset($this->principals[$principalKey]);
            }
        }
        unset($this->connections[$key]);
    }

    public function terminate(Application $application, string $principal, ?string $generation = null): int
    {
        if (preg_match('/^[A-Za-z0-9_-]{32,128}$/D', $principal) !== 1
            || ($generation !== null && preg_match('/^[A-Za-z0-9_-]{32,128}$/D', $generation) !== 1)) {
            throw new InvalidArgumentException('Invalid connection authority termination.');
        }
        $keys = array_keys($this->principals[$this->principalKey($application, $principal)] ?? []);
        $terminated = 0;
        foreach ($keys as $key) {
            $authority = $this->connections[$key]['authority'] ?? null;
            if (! $authority instanceof ConnectionAuthority
                || ($generation !== null && ! hash_equals($generation, $authority->generation))) {
                continue;
            }
            $this->terminateConnection($key);
            $terminated++;
        }
        ConnectionAuthorityTerminated::dispatch($application, $terminated, 'server_control');

        return $terminated;
    }

    public function updateLease(
        Application $application,
        string $principal,
        string $generation,
        int $revision,
        int $expiresAt,
    ): int {
        if (preg_match('/^[A-Za-z0-9_-]{32,128}$/D', $principal) !== 1
            || preg_match('/^[A-Za-z0-9_-]{32,128}$/D', $generation) !== 1
            || $revision < 1
            || $expiresAt < 1
            || $expiresAt > time() + 86400) {
            throw new InvalidArgumentException('Invalid connection lease update.');
        }
        $keys = array_keys($this->principals[$this->principalKey($application, $principal)] ?? []);
        $updated = 0;
        foreach ($keys as $key) {
            $state = $this->connections[$key] ?? null;
            $current = $state['authority'] ?? null;
            if ($state === null || $state['terminal'] || ! $current instanceof ConnectionAuthority
                || ! hash_equals($generation, $current->generation)
                || $revision <= $current->revision) {
                continue;
            }
            if ($expiresAt <= time()) {
                $this->terminateConnection($key);
                $updated++;

                continue;
            }
            $updatedAuthority = new ConnectionAuthority(
                $current->principal,
                $current->generation,
                $revision,
                $expiresAt,
                $current->normalizedUserData,
            );
            $this->connections[$key]['authority'] = $updatedAuthority;
            $this->scheduleExpiry($key, $updatedAuthority);
            $updated++;
        }
        ConnectionAuthorityLeaseUpdated::dispatch($application, $updated);

        return $updated;
    }

    private function scheduleExpiry(string $key, ConnectionAuthority $authority): void
    {
        $timer = $this->connections[$key]['timer'] ?? null;
        if ($timer instanceof TimerInterface) {
            $this->loop->cancelTimer($timer);
        }
        $capturedGeneration = $authority->generation;
        $capturedRevision = $authority->revision;
        $this->connections[$key]['timer'] = $this->loop->addTimer(
            max(0.001, $authority->expiresAt - time()),
            function () use ($key, $capturedGeneration, $capturedRevision): void {
                $state = $this->connections[$key] ?? null;
                $current = $state['authority'] ?? null;
                if ($state !== null
                    && $current instanceof ConnectionAuthority
                    && hash_equals($capturedGeneration, $current->generation)
                    && $capturedRevision === $current->revision
                    && ! $current->isCurrent()) {
                    $application = $state['connection']->app();
                    $this->terminateConnection($key);
                    ConnectionAuthorityTerminated::dispatch(
                        $application,
                        1,
                        'deadline_expired',
                    );
                }
            },
        );
    }

    private function terminateConnection(string $key): void
    {
        $state = $this->connections[$key] ?? null;
        if ($state === null || $state['terminal']) {
            return;
        }
        $this->connections[$key]['terminal'] = true;
        $state['connection']->terminate();
        $this->remove($state['connection']);
    }

    private function connectionKey(Connection $connection): string
    {
        return $connection->app()->id().':'.$connection->id();
    }

    private function principalKey(Application $application, string $principal): string
    {
        return $application->id().':'.$principal;
    }
}
