<?php

namespace Firesphere\GraphQLJWT;

use GraphQL\Type\Definition\Type;
use SilverStripe\GraphQL\TypeCreator;

class ValidateTokenTypeCreator extends TypeCreator
{
    public function attributes()
    {
        return [
            'name' => 'ValidateToken'
        ];
    }

    public function fields()
    {
        return [
            'Valid'   => ['type' => Type::boolean()],
            'Message' => ['type' => Type::string()],
            'Code'    => ['type' => Type::int()],
        ];
    }
}
