<?php

namespace MySite\GraphQL;

use GraphQL\Type\Definition\Type;
use SilverStripe\GraphQL\TypeCreator;

class MemberTypeCreator extends TypeCreator
{
    public function attributes()
    {
        return [
            'name' => 'member'
        ];
    }

    public function fields()
    {
        return [
            'ID' => ['type' => Type::int()],
            'FirstName' => ['type' => Type::string()],
            'Surname' => ['type' => Type::string()],
            'Email' => ['type' => Type::string()],
            'Password' => ['type' => Type::nonNull(Type::string())],
            'Token' => ['type' => Type::string()]
        ];
    }
}
