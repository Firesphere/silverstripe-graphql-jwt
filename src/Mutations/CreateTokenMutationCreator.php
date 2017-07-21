<?php

namespace Firesphere\GraphQLJWT;

use GraphQL\Type\Definition\ResolveInfo;
use GraphQL\Type\Definition\Type;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\GraphQL\MutationCreator;
use SilverStripe\GraphQL\OperationResolver;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

class CreateTokenMutationCreator extends MutationCreator implements OperationResolver
{
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
     * @param mixed $object
     * @param array $args
     * @param mixed $context
     * @param ResolveInfo $info
     * @return null|Member|static
     */
    public function resolve($object, array $args, $context, ResolveInfo $info)
    {
        $security = Injector::inst()->get(Security::class);
        $authenticators = $security->getApplicableAuthenticators(Authenticator::LOGIN);
        $request = Controller::curr()->getRequest();
        $member = null;

        if (count($authenticators)) {
            foreach ($authenticators as $authenticator) {
                $member = $authenticator->authenticate($args, $request, $result);
                if ($result->isValid()) {
                    break;
                }
            }
        }
        $authenticator = Injector::inst()->get(JWTAuthenticator::class);

        if ($member instanceof Member) {
            $member->Token = $authenticator->generateToken($member);
        } elseif (JWTAuthenticator::config()->get('anonymous_allowed')) {
            $member = Member::create(['ID' => 0, 'FirstName' => 'Anonymous']);
            // Create an anonymous token
            $member->Token = $authenticator->generateToken($member);
        } else {
            Security::setCurrentUser(null);
            Injector::inst()->get(IdentityStore::class)->logOut();

            // Return a token-less member
            return Member::create();
        }

        return $member;
    }
}
