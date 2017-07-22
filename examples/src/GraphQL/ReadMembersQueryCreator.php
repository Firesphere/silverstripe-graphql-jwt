<?php

namespace MySite\GraphQL;

use GraphQL\Type\Definition\ResolveInfo;
use GraphQL\Type\Definition\Type;
use SilverStripe\Security\Member;
use SilverStripe\GraphQL\OperationResolver;
use SilverStripe\GraphQL\QueryCreator;
use SilverStripe\Security\Security;

class ReadMembersQueryCreator extends QueryCreator implements OperationResolver
{
    public function attributes()
    {
        return [
            'name' => 'readMembers'
        ];
    }

    public function args()
    {
        return [
            'ID' => ['type' => Type::string()],
            'Email' => ['type' => Type::string()],
            'Token' => ['type' => Type::string()]
        ];
    }

    public function type()
    {
        return Type::listOf($this->manager->getType('member'));
    }

    public function resolve($object, array $args, $context, ResolveInfo $info)
    {
        $list = Member::get();

        // Optional filtering by properties
        if (isset($args['Email'])) {
            $list = $list->filter('Email', $args['Email']);
        }
        if (isset($args['ID'])) {
            $list = $list->byID($args['ID']);
        }

        return $list;
    }
}
