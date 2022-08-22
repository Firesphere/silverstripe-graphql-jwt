<?php

namespace Firesphere\GraphQLJWT\Extensions;


use Firesphere\GraphQLJWT\Resolvers\Resolver;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;
use SilverStripe\Security\Permission;

class ExtendedMemberAuthenticator extends MemberAuthenticator
{

  protected function authenticateMember($data, ValidationResult &$result = null, Member $member = null)
  {
    $member = parent::authenticateMember($data, $result, $member);
    if ($member && (!Permission::checkMember($member, 'ADMIN') && !$member->isActivated)) {
      $result->addError(
        _t('JWT.STATUS_INACTIVATED_USER', 'User is not activated. Please check your email for activation link or request a new one.'),
        Resolver::STATUS_INACTIVATED_USER,
      );
      return null;
    }
    return $member;
  }
}
