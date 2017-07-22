<?php

namespace MySite\GraphQL;

use Firesphere\GraphQLJWT\JWTAuthenticator;
use GraphQL\Type\Definition\ResolveInfo;
use GraphQL\Type\Definition\Type;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\GraphQL\MutationCreator;
use SilverStripe\GraphQL\OperationResolver;
use SilverStripe\Security\Member;

class CreateMemberMutationCreator extends MutationCreator implements OperationResolver
{
    public function attributes()
    {
        return [
            'name'        => 'createMember',
            'description' => 'Creates a member without permissions or group assignments'
        ];
    }

    public function type()
    {
        return $this->manager->getType('member');
    }

    public function args()
    {
        return [
            'FirstName' => ['type' => Type::string()],
            'Surname'   => ['type' => Type::string()],
            'Email'     => ['type' => Type::nonNull(Type::string())],
            'Password'  => ['type' => Type::nonNull(Type::string())],
            'Token'     => ['type' => Type::string()]
        ];
    }

    public function resolve($object, array $args, $context, ResolveInfo $info)
    {
        if (!Member::get()->filter(['Email' => $args['Email']])->count()) {
            /** @var Member $member */
            $member = Member::create($args);
            $id = $member->write();
            $member->ID = $id;
            $token = Injector::inst()->get(JWTAuthenticator::class)->generateToken($member);
            $member->Token = $token;
            $member->addToGroupByCode('administrators');
        } else {
            // Return an empty member. This makes it easier to capture an error
            $member = Member::create();
        }

        return $member;
    }
}
