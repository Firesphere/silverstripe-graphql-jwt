<?php

namespace Firesphere\GraphQLJWT;

use GraphQL\Type\Definition\Type;
use SilverStripe\GraphQL\TypeCreator;

class MemberTokenTypeCreator extends TypeCreator
{
    public function attributes()
    {
        return [
            'name' => 'MemberToken'
        ];
    }

    public function fields()
    {
        return [
            'ID'        => ['type' => Type::id()],
            'FirstName' => ['type' => Type::string()],
            'Surname'   => ['type' => Type::string()],
            'Email'     => ['type' => Type::string()],
            'Token'     => ['type' => Type::string()]
        ];
    }
}
