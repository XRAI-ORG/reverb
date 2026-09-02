<?php

namespace Laravel\Reverb\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Laravel\Reverb\Application;

final class ConnectionAuthorityAuthenticated
{
    use Dispatchable;

    public function __construct(public Application $application) {}
}
