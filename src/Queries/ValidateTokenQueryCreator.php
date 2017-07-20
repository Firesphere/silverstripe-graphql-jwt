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
        return [];
    }

    public function type()
    {
        return Type::boolean();
    }

    public function resolve($object, array $args, $context, ResolveInfo $info)
    {
        $validator = Injector::inst()->get(JWTAuthenticator::class);

        $request = Controller::curr()->getRequest();
        $authHeader = $request->getHeader('Authorization');
        $member = null;
        if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            $member = $validator->authenticate(['token' => $matches[1]], $request);
        }

        return $member instanceof Member;
    }
}
