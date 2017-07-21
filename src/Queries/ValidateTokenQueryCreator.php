<?php

namespace Firesphere\GraphQLJWT;

use GraphQL\Type\Definition\ResolveInfo;
use GraphQL\Type\Definition\Type;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\GraphQL\OperationResolver;
use SilverStripe\GraphQL\QueryCreator;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;

class ValidateTokenQueryCreator extends QueryCreator implements OperationResolver
{
    public function attributes()
    {
        return [
            'name' => 'validateToken',
            'description' => 'Validates a given token from the Bearer header'
        ];
    }

    public function args()
    {
        return [];
    }

    public function type()
    {
        return $this->manager->getType('ValidateToken');
    }

    public function resolve($object, array $args, $context, ResolveInfo $info)
    {
        $validator = Injector::inst()->get(JWTAuthenticator::class);
        $msg = [];
        $request = Controller::curr()->getRequest();
        $authHeader = $request->getHeader('Authorization');
        $result = new ValidationResult();
        if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            $validator->authenticate(['token' => $matches[1]], $request, $result);
        } else {
            $result->addError('No Bearer token found');
        }

        foreach($result->getMessages() as $message) {
            $msg[] = $message['message'];
        }

        $return = ['Valid' => $result->isValid(),'Message' => implode('; ', $msg)];

        return $return;
    }
}
