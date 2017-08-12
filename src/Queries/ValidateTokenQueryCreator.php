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
            'name'        => 'validateToken',
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
     * @throws \Psr\Container\NotFoundExceptionInterface
     * @throws \OutOfBoundsException
     * @throws \BadMethodCallException
     */
    public function resolve($object, array $args, $context, ResolveInfo $info)
    {
        /** @var JWTAuthenticator $authenticator */
        $authenticator = Injector::inst()->get(JWTAuthenticator::class);
        $msg = [];
        $request = Controller::curr()->getRequest();
        $matches = HeaderExtractor::getAuthorizationHeader($request);
        $result = new ValidationResult();
        $code = 401;

        if (!empty($matches[1])) {
            $authenticator->authenticate(['token' => $matches[1]], $request, $result);
            if ($result->isValid()) {
                $code = 200;
            }
        } else {
            $result->addError('No Bearer token found');
        }

        foreach ($result->getMessages() as $message) {
            if (strpos($message['message'], 'Token is expired') === 0) {
                // An expired token is code 426 `Update required`
                $code = 426;
            }
            $msg[] = $message['message'];
        }

        return ['Valid' => $result->isValid(), 'Message' => implode('; ', $msg), 'Code' => $code];
    }
}
