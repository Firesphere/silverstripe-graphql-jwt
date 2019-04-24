<?php declare(strict_types=1);

namespace Firesphere\GraphQLJWT\Helpers;

use LogicException;
use SilverStripe\Core\Environment;

trait RequiresConfig
{
    /**
     * Get an environment value. If $default is not set and the environment isn't set either this will error.
     *
     * @param string $key
     * @param mixed $default
     * @throws LogicException Error if environment variable is required, but not configured
     * @return mixed
     */
    public static function getEnv(string $key, $default = null)
    {
        $value = Environment::getEnv($key);
        if ($value) {
            return $value;
        }
        if (func_num_args() === 1) {
            throw new LogicException("Required environment variable {$key} not set");
        }
        return $default;
    }
}
