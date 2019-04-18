<?php declare(strict_types=1);

namespace Firesphere\GraphQLJWT\Authentication;

use BadMethodCallException;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\ORM\ValidationException;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;

class AnonymousUserAuthenticator extends MemberAuthenticator
{
    use Configurable;
    use Injectable;

    /**
     * Anonymous username
     *
     * @var string
     */
    private static $anonymous_username = 'anonymous';

    /**
     * Default field values to assign to anonymous user
     *
     * @var array
     */
    private static $anonymous_fields = [
        'FirstName' => 'Anonymous',
    ];

    public function supportedServices(): int
    {
        return Authenticator::LOGIN | Authenticator::LOGOUT;
    }

    public function authenticate(array $data, HTTPRequest $request, ValidationResult &$result = null): ?Member
    {
        // Only applies to request for anonymous user specifically
        $email = $data['Email'] ?? null;
        if ($email !== static::config()->get('anonymous_username')) {
            return null;
        }

        return parent::authenticate($data, $request, $result);
    }

    /**
     * Attempt to find and authenticate member if possible from the given data
     *
     * @skipUpgrade
     * @param array            $data Form submitted data
     * @param ValidationResult $result
     * @param Member           $member This third parameter is used in the CMSAuthenticator(s)
     * @return Member Found member, regardless of successful login
     * @throws ValidationException
     */
    protected function authenticateMember($data, ValidationResult &$result = null, Member $member = null): Member
    {
        // Get user, or create if not exists
        $member = $this->getOrCreateAnonymousMember();

        // Validate this member is still allowed to login
        $result = $result ?: ValidationResult::create();
        $member->validateCanLogin($result);

        // Emit failure to member and form (if available)
        if ($result->isValid()) {
            $member->registerSuccessfulLogin();
        } else {
            $member->registerFailedLogin();
        }

        return $member;
    }

    public function checkPassword(Member $member, $password, ValidationResult &$result = null)
    {
        throw new BadMethodCallException("checkPassword not supported for anonymous users");
    }

    /**
     * Build a new datarecord to contain the anonymous user
     *
     * @return Member
     * @throws ValidationException
     */
    protected function getOrCreateAnonymousMember()
    {
        // Fun facts about anonymous members
        $identifierField = Member::config()->get('unique_identifier_field');
        $username = static::config()->get('anonymous_username');
        $fields = static::config()->get('anonymous_fields');

        // Find existing member
        /** @var Member $member */
        $member = Member::get()->find($identifierField, $username);
        $this->extend('updateExistingAnonymousMember', $member);
        if ($member) {
            return $member;
        }

        // Create new member
        $member = Member::create();
        $member->{$identifierField} = $username;
        $member->update($fields);
        $this->extend('updateCreatedAnonymousMember', $member);
        $member->write();
        return $member;
    }
}
