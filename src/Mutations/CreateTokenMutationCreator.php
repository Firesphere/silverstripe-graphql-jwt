<?php

namespace Firesphere\GraphQLJWT\Mutations;

use App\Users\GraphQL\Types\TokenStatusEnum;
use Firesphere\GraphQLJWT\Authentication\JWTAuthenticator;
use Firesphere\GraphQLJWT\Extensions\MemberExtension;
use Firesphere\GraphQLJWT\Helpers\GeneratesTokenOutput;
use Firesphere\GraphQLJWT\Helpers\RequiresAuthenticator;
use GraphQL\Type\Definition\ResolveInfo;
use GraphQL\Type\Definition\Type;
use Psr\Container\NotFoundExceptionInterface;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\GraphQL\MutationCreator;
use SilverStripe\GraphQL\OperationResolver;
use SilverStripe\ORM\ValidationException;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

class CreateTokenMutationCreator extends MutationCreator implements OperationResolver
{
    use RequiresAuthenticator;
    use GeneratesTokenOutput;

    public function attributes()
    {
        return [
            'name'        => 'createToken',
            'description' => 'Creates a JWT token for a valid user'
        ];
    }

    public function type()
    {
        return $this->manager->getType('MemberToken');
    }

    public function args()
    {
        return [
            'Email'    => ['type' => Type::nonNull(Type::string())],
            'Password' => ['type' => Type::nonNull(Type::string())]
        ];
    }

    /**
     * @param mixed       $object
     * @param array       $args
     * @param mixed       $context
     * @param ResolveInfo $info
     * @return array
     * @throws NotFoundExceptionInterface
     * @throws HTTPResponse_Exception
     * @throws ValidationException
     */
    public function resolve($object, array $args, $context, ResolveInfo $info)
    {
        // Authenticate this member
        $request = Controller::curr()->getRequest();
        $member = $this->getAuthenticatedMember($args, $request);

        // Handle unauthenticated
        if (!$member) {
            return $this->generateResponse(TokenStatusEnum::STATUS_BAD_LOGIN);
        }

        // Create new token from this member
        $authenticator = $this->getJWTAuthenticator();
        $token = $authenticator->generateToken($request, $member->getJWTData(), $member);
        return $this->generateResponse(TokenStatusEnum::STATUS_OK, $member, $token);
    }

    /**
     * Get an authenticated member from the given request
     *
     * @param array       $args
     * @param HTTPRequest $request
     * @return Member|MemberExtension
     */
    protected function getAuthenticatedMember(array $args, HTTPRequest $request): Member
    {
        /** @var Security $security */
        $security = Injector::inst()->get(Security::class);
        $authenticators = $security->getApplicableAuthenticators(Authenticator::LOGIN);

        // Login with authenticators
        foreach ($authenticators as $authenticator) {
            // Skip JWT authenticator itself
            if ($authenticator instanceof JWTAuthenticator) {
                continue;
            }

            // Check if we can authenticate
            $result = new ValidationResult();
            $member = $authenticator->authenticate($args, $request, $result);
            if ($member && $result->isValid()) {
                return $member;
            }
        }

        return null;
    }
}
