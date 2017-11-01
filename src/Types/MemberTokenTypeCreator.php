<?php

namespace Firesphere\GraphQLJWT\Types;

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
        $string = Type::string();
        $id = Type::id();

        return [
            'ID'        => ['type' => $id],
            'FirstName' => ['type' => $string],
            'Surname'   => ['type' => $string],
            'Email'     => ['type' => $string],
            'Token'     => ['type' => $string]
        ];
    }
}
