<?php

namespace Laravel\Reverb\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Laravel\Reverb\Application;

final class ConnectionAuthorityLeaseUpdated
{
    use Dispatchable;

    public function __construct(
        public Application $application,
        public int $connectionCount,
    ) {}
}
