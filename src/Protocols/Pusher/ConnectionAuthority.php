<?php

namespace Laravel\Reverb\Protocols\Pusher;

use InvalidArgumentException;

final readonly class ConnectionAuthority
{
    private const MAX_LEASE_SECONDS = 86400;

    public function __construct(
        public string $principal,
        public string $generation,
        public int $revision,
        public int $expiresAt,
        public string $normalizedUserData,
    ) {}

    public static function fromUserData(string $userData, ?int $now = null): self
    {
        $now ??= time();
        if ($userData === '' || strlen($userData) > 4096) {
            throw new InvalidArgumentException('Invalid connection authentication data.');
        }
        $decoded = json_decode($userData, true, flags: JSON_THROW_ON_ERROR);
        if (! is_array($decoded)
            || array_diff(array_keys($decoded), ['id', 'user_info', 'watchlist', 'xrai_reverb']) !== []
            || ! isset($decoded['id'], $decoded['xrai_reverb'])
            || ! is_string($decoded['id'])
            || preg_match('/^[A-Za-z0-9_-]{32,128}$/D', $decoded['id']) !== 1
            || ! is_array($decoded['xrai_reverb'])
            || count($decoded['xrai_reverb']) !== 4
            || array_diff(array_keys($decoded['xrai_reverb']), ['version', 'authority', 'revision', 'expires_at']) !== []) {
            throw new InvalidArgumentException('Invalid connection authentication data.');
        }
        $lease = $decoded['xrai_reverb'];
        if (($lease['version'] ?? null) !== 1
            || ! is_string($lease['authority'] ?? null)
            || preg_match('/^[A-Za-z0-9_-]{32,128}$/D', $lease['authority']) !== 1
            || ! is_int($lease['revision'] ?? null)
            || $lease['revision'] < 1
            || ! is_int($lease['expires_at'] ?? null)
            || $lease['expires_at'] <= $now
            || $lease['expires_at'] > $now + self::MAX_LEASE_SECONDS
            || (array_key_exists('user_info', $decoded) && ! is_array($decoded['user_info']))
            || (array_key_exists('watchlist', $decoded)
                && (! is_array($decoded['watchlist']) || ! array_is_list($decoded['watchlist'])))) {
            throw new InvalidArgumentException('Invalid connection authentication data.');
        }
        foreach ($decoded['watchlist'] ?? [] as $watch) {
            if (! is_string($watch) || $watch === '' || strlen($watch) > 128) {
                throw new InvalidArgumentException('Invalid connection authentication data.');
            }
        }
        $normalized = json_encode($decoded, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        return new self(
            $decoded['id'],
            $lease['authority'],
            $lease['revision'],
            $lease['expires_at'],
            $normalized,
        );
    }

    public function isCurrent(?int $now = null): bool
    {
        return ($now ?? time()) < $this->expiresAt;
    }

    public function sameIdentity(self $other): bool
    {
        return hash_equals($this->principal, $other->principal)
            && hash_equals($this->generation, $other->generation);
    }
}
