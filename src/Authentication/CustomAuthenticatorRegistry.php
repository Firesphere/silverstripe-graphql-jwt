<?php


namespace Firesphere\GraphQLJWT\Authentication;


use Firesphere\GraphQLJWT\Mutations\CreateTokenMutationCreator;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Security\Authenticator;

class CustomAuthenticatorRegistry
{
    use Injectable;

    /**
     * Extra authenticators to use for logging in with username / password
     *
     * @var Authenticator[]
     */
    protected $customAuthenticators = [];

    /**
     * @return Authenticator[]
     */
    public function getCustomAuthenticators(): array
    {
        return $this->customAuthenticators;
    }

    /**
     * @param Authenticator[] $authenticators
     * @return $this
     */
    public function setCustomAuthenticators(array $authenticators): self
    {
        $this->customAuthenticators = $authenticators;
        return $this;
    }

}
