<?php

namespace Laravel\Reverb\Protocols\Pusher\Contracts;

use Laravel\Reverb\Application;
use Laravel\Reverb\Contracts\Connection;
use Laravel\Reverb\Protocols\Pusher\ConnectionAuthority;

interface ConnectionAuthorityRegistry
{
    public function register(Connection $connection): void;

    public function authenticate(Connection $connection, ConnectionAuthority $authority): ConnectionAuthority;

    public function authority(Connection $connection): ?ConnectionAuthority;

    public function permitsProtectedTraffic(Connection $connection): bool;

    public function remove(Connection $connection): void;

    public function terminate(Application $application, string $principal, ?string $generation = null): int;

    public function updateLease(
        Application $application,
        string $principal,
        string $generation,
        int $revision,
        int $expiresAt,
    ): int;
}
