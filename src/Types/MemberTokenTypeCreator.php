<?php

namespace Firesphere\GraphQLJWT\Types;

use App\Users\GraphQL\Types\TokenStatusEnum;
use GraphQL\Type\Definition\Type;
use SilverStripe\GraphQL\TypeCreator;

/**
 * Represents a member / token pair
 */
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
            'Valid'  => ['type' => Type::boolean()],
            'Member' => ['type' => $this->manager->getType('Member')],
            'Token'  => ['type' => Type::string()],
            'Status' => ['type' => TokenStatusEnum::instance()],
            'Code'   => ['type' => Type::int()],
        ];
    }
}
