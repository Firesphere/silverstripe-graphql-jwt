<?php declare(strict_types=1);

namespace App\Users\GraphQL\Types;

use GraphQL\Type\Definition\Type;
use SilverStripe\GraphQL\TypeCreator;

/**
 * A logged in member
 */
class MemberTypeCreator extends TypeCreator
{
    public function attributes(): array
    {
        return ['name' => 'Member'];
    }

    public function fields(): array
    {
        return [
            'ID'        => ['type' => Type::int()],
            'FirstName' => ['type' => Type::string()],
            'Surname'   => ['type' => Type::string()],
            'Email'     => ['type' => Type::string()],
            'Token'     => ['type' => Type::string()],
            'Message'   => ['type' => Type::string()],
        ];
    }
}
