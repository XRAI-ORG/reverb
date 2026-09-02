<?php

namespace Laravel\Reverb;

use Composer\InstalledVersions;

final class BuildIdentity
{
    /**
     * Get the installed package version.
     */
    public static function version(): string
    {
        $version = InstalledVersions::getPrettyVersion('laravel/reverb');

        return is_string($version) && preg_match('/^[A-Za-z0-9._+-]{1,64}$/D', $version) === 1
            ? $version
            : 'unknown';
    }

    /**
     * Get the installed package source reference.
     */
    public static function reference(): string
    {
        $reference = InstalledVersions::getReference('laravel/reverb');

        return is_string($reference) && preg_match('/^[0-9a-f]{7,40}$/D', $reference) === 1
            ? $reference
            : 'unknown';
    }
}
