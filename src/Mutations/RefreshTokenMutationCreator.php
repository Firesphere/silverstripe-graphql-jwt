<?php

namespace Firesphere\GraphQLJWT;

use GraphQL\Type\Definition\ResolveInfo;
use GraphQL\Type\Definition\Type;
use Lcobucci\JWT\Token;
use SilverStripe\GraphQL\MutationCreator;
use SilverStripe\GraphQL\OperationResolver;

class RefreshTokenMutationCreator extends MutationCreator implements OperationResolver
{
    public function attributes()
    {
        return [
            'name' => 'refreshToken',
            'description' => 'Refreshes a JWT token for a valid user. To be done'
        ];
    }

    public function type()
    {
        return Type::string();//$this->manager->getType('member');
    }

    public function args()
    {
        return [
            'ExpiredToken' => ['type' => Type::nonNull(Type::string())]
        ];
    }

    /**
     * @todo Make it refresh things, it just returns an auth result now
     * @param mixed       $object
     * @param array       $args
     * @param mixed       $context
     * @param ResolveInfo $info
     * @return Token|string
     */
    public function resolve($object, array $args, $context, ResolveInfo $info)
    {
        return 'TODO';
    }

}
