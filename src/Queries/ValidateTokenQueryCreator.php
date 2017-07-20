<?php

namespace Firesphere\GraphQLJWT;


use GraphQL\Type\Definition\ResolveInfo;
use GraphQL\Type\Definition\Type;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\GraphQL\OperationResolver;
use SilverStripe\GraphQL\QueryCreator;
use SilverStripe\Security\Member;

class ValidateTokenQueryCreator extends QueryCreator implements OperationResolver
{
    public function attributes()
    {
        return [
            'name' => 'validateToken'
        ];
    }

    public function args()
    {
        return [
            'Token' => ['type' => Type::string()]
        ];
    }

    public function type()
    {
        return Type::boolean();
    }

    public function resolve($object, array $args, $context, ResolveInfo $info)
    {
        $validator = Injector::inst()->get(JWTAuthenticator::class);
        /** @var array $data Authenticator expects lower case 'token' */
        $data = ['token' => $args['Token']];

        $request = Controller::curr()->getRequest();
        $result = $validator->authenticate($data, $request);

        return $result instanceof Member;

    }
}
