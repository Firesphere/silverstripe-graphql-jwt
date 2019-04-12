<?php

namespace Firesphere\GraphQLJWT\Helpers;

class PathResolver
{
    /**
     * Return an absolute path from a relative one
     * If the path doesn't exist, returns null
     *
     * @param string       $path
     * @param mixed|string $base
     * @return string|null
     */
    public static function resolve($path, $base = BASE_PATH)
    {
        if (strstr($path, '/') !== 0) {
            $path = $base . '/' . $path;
        }
        return realpath($path) ?: null;
    }
}
