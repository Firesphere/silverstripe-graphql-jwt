<?php declare(strict_types=1);

namespace Firesphere\GraphQLJWT\Helpers;

use Firesphere\GraphQLJWT\Authentication\JWTAuthenticator;

/**
 * Parent class requires a JWTAuthenticator instance to be injected
 */
trait RequiresAuthenticator
{
    /**
     * @var JWTAuthenticator|null
     */
    protected $jwtAuthenticator = null;

    /**
     * @return JWTAuthenticator|null
     */
    protected function getJWTAuthenticator(): ?JWTAuthenticator
    {
        return $this->jwtAuthenticator;
    }

    /**
     * Inject authenticator this mutation should use
     *
     * @param JWTAuthenticator $authenticator
     * @return $this
     */
    public function setJWTAuthenticator(JWTAuthenticator $authenticator): self
    {
        $this->jwtAuthenticator = $authenticator;
        return $this;
    }
}
