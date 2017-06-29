<?php

namespace Firesphere\GraphQLJWT;


use GraphQL\Type\Definition\ResolveInfo;
use GraphQL\Type\Definition\Type;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\GraphQL\MutationCreator;
use SilverStripe\GraphQL\OperationResolver;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

class CreateTokenMutationCreator extends MutationCreator implements OperationResolver
{
    public function attributes()
    {
        return [
            'name' => 'createToken',
            'description' => 'Creates a JWT token for a valid user'
        ];
    }

    public function type()
    {
        return function () {
            return Type::string();
        };
    }

    public function args()
    {
        return [
            'Email' => ['type' => Type::nonNull(Type::string())],
            'Password' => ['type' => Type::nonNull(Type::string())]
        ];
    }

    public function resolve($object, array $args, $context, ResolveInfo $info)
    {
        $authenticators = Security::singleton()->getApplicableAuthenticators(Authenticator::LOGIN);
        $request = Controller::curr()->getRequest();
        $member = null;

        if(count($authenticators)) {
            foreach($authenticators as $authenticator) {
                $member = $authenticator->authenticate($args, $request, $result);
                if($result->isValid()) {
                    break;
                }
            }
        }
        $authenticator = Injector::inst()->get(JWTAuthenticator::class);

        if($member instanceof Member) {
            $token = $authenticator->generateToken($member);
        } else {
            // Create an anonymous token
            $token = $authenticator->generateToken(Member::create(['ID' => 0, 'FirstName' => 'Anonymous']));
        }

        return $token;
    }

}