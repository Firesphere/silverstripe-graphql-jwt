<?php

namespace Firesphere\GraphQLJWT\Helpers;

use Firesphere\GraphQLJWT\Authentication\JWTAuthenticator;

/**
 * Parent class requires a JWTAuthenticator instance to be injected
 */
trait RequiresAuthenticator
{
    /**
     * @var JWTAuthenticator
     */
    protected $jwtAuthenticator = null;

    /**
     * @return JWTAuthenticator
     */
    protected function getJWTAuthenticator()
    {
        return $this->jwtAuthenticator;
    }

    /**
     * Inject authenticator this mutation should use
     *
     * @param JWTAuthenticator $authenticator
     * @return $this
     */
    public function setJWTAuthenticator(JWTAuthenticator $authenticator)
    {
        $this->jwtAuthenticator = $authenticator;
        return $this;
    }
}
