<?php

namespace Firesphere\GraphQLJWT;

use GraphQL\Type\Definition\ResolveInfo;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\GraphQL\OperationResolver;
use SilverStripe\GraphQL\QueryCreator;
use SilverStripe\ORM\ValidationResult;

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

    /**
     * @param mixed $object
     * @param array $args
     * @param mixed $context
     * @param ResolveInfo $info
     * @return array
     * @throws \BadMethodCallException
     */
    public function resolve($object, array $args, $context, ResolveInfo $info)
    {
        $validator = Injector::inst()->get(JWTAuthenticator::class);
        $msg = [];
        $request = Controller::curr()->getRequest();
        $matches = HeaderExtractor::getAuthorizationHeader($request);
        $result = new ValidationResult();

        if (!empty($matches[1])) {
            $validator->authenticate(['token' => $matches[1]], $request, $result);
        } else {
            $result->addError('No Bearer token found');
        }

        foreach ($result->getMessages() as $message) {
            $msg[] = $message['message'];
        }

        return ['Valid' => $result->isValid(), 'Message' => implode('; ', $msg)];
    }
}
