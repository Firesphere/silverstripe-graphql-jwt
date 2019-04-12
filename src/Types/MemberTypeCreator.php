<?php

namespace App\Users\GraphQL\Types;

use GraphQL\Type\Definition\Type;
use SilverStripe\GraphQL\TypeCreator;

/**
 * A logged in member
 */
class MemberTypeCreator extends TypeCreator
{
    public function attributes()
    {
        return ['name' => 'Member'];
    }

    public function fields()
    {
        return [
            'ID'        => ['type' => Type::int()],
            'FirstName' => ['type' => Type::string()],
            'Surname'   => ['type' => Type::string()],
            'Email'     => ['type' => Type::string()],
            'Token'     => ['type' => Type::string()]
        ];
    }
}
