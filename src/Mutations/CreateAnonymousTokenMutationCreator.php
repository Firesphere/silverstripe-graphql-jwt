<?php

namespace Firesphere\GraphQLJWT\Mutations;

use BadMethodCallException;
use Firesphere\GraphQLJWT\Authentication\JWTAuthenticator;
use Firesphere\GraphQLJWT\Helpers\RequiresAuthenticator;
use GraphQL\Type\Definition\ResolveInfo;
use GraphQL\Type\Definition\Type;
use Psr\Container\NotFoundExceptionInterface;
use SilverStripe\Control\Controller;
use SilverStripe\GraphQL\MutationCreator;
use SilverStripe\GraphQL\OperationResolver;
use SilverStripe\ORM\ValidationException;

class CreateAnonymousTokenMutationCreator extends MutationCreator implements OperationResolver
{
    use RequiresAuthenticator;

    public function attributes()
    {
        return [
            'name'        => 'createAnonymousToken',
            'description' => 'Creates a JWT token for an anonymous user. No email / password is required.'
        ];
    }

    public function type()
    {
        return Type::string();
    }

    public function args()
    {
        return [];
    }

    /**
     * @param mixed       $object
     * @param array       $args
     * @param mixed       $context
     * @param ResolveInfo $info
     * @return string The anonymous JWT token
     * @throws NotFoundExceptionInterface
     * @throws ValidationException
     */
    public function resolve($object, array $args, $context, ResolveInfo $info)
    {
        // Verify anonymous tokens are allowed
        if (JWTAuthenticator::config()->get('anonymous_allowed')) {
            throw new BadMethodCallException('Anonymous JWT authentication is forbidden');
        }

        $request = Controller::curr()->getRequest();

        // Create new token with anonymous payload
        $authenticator = $this->getJWTAuthenticator();
        $token = $authenticator->generateToken($request, $this->getJWTData());
        return $token->__toString();
    }

    /**
     * Get JWT subject data for anonymous user
     *
     * @return false|string
     */
    protected function getJWTData()
    {
        return json_encode(['type' => 'anonymous']);
    }
}
