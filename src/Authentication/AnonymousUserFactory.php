<?php

namespace Firesphere\GraphQLJWT\Authentication;

use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Factory;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Security\Member;

class AnonymousUserFactory implements Factory
{
    use Configurable;

    /**
     * Default field values to assign to anonymous user
     *
     * @var array
     */
    private static $anonymous_fields = [
        'FirstName' => 'Anonymous',
    ];

    /**
     * Creates a new service instance.
     *
     * @param string $service The class name of the service.
     * @param array $params The constructor parameters.
     * @return Member The member that was created
     * @throws ValidationException
     */
    public function create($service, array $params = array())
    {
        // In case we configure multiple users
        $username = $params['username'] ?? 'anonymous';
        $identifierField = Member::config()->get('unique_identifier_field');
        $fields = static::config()->get('anonymous_fields');

        // Find existing member
        /** @var Member $member */
        $member = Member::get()->find($identifierField, $username);
        if ($member) {
            return $member;
        }

        // Create new member
        $member = Member::create();
        $member->{$identifierField} = $username;
        $member->update($fields);
        $member->write();
        return $member;
    }
}
