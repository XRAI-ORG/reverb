<?php

namespace Laravel\Reverb\Protocols\Pusher;

use Laravel\Reverb\Application;

final class ConnectionAuthorityControlSignature
{
    public static function sign(Application $application, string $type, array $payload): string
    {
        return hash_hmac(
            'sha256',
            $type."\n".json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            $application->secret(),
        );
    }

    public static function valid(
        Application $application,
        string $type,
        array $payload,
        mixed $signature,
    ): bool {
        return is_string($signature)
            && hash_equals(self::sign($application, $type, $payload), $signature);
    }
}
