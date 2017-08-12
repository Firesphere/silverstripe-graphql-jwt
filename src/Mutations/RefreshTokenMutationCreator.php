<?php

namespace Firesphere\GraphQLJWT;

use GraphQL\Type\Definition\ResolveInfo;
use Lcobucci\JWT\Parser;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\GraphQL\MutationCreator;
use SilverStripe\GraphQL\OperationResolver;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;

class RefreshTokenMutationCreator extends MutationCreator implements OperationResolver
{
    public function attributes()
    {
        return [
            'name' => 'refreshToken',
            'description' => 'Refreshes a JWT token for a valid user. To be done'
        ];
    }

    public function type()
    {
        return $this->manager->getType('MemberToken');
    }

    public function args()
    {
        return [];
    }

    /**
     * @param mixed $object
     * @param array $args
     * @param mixed $context
     * @param ResolveInfo $info
     * @return Member|null
     * @throws \BadMethodCallException
     * @throws \OutOfBoundsException
     */
    public function resolve($object, array $args, $context, ResolveInfo $info)
    {
        $request = Controller::curr()->getRequest();
        $authenticator = Injector::inst()->get(JWTAuthenticator::class);
        $member = null;
        $result = new ValidationResult();
        $matches = HeaderExtractor::getAuthorizationHeader($request);

        if (!empty($matches[1])) {
            $member = $authenticator->authenticate(['token' => $matches[1]], $request, $result);
        }

        $expired = false;
        if ($member === null) {
            foreach ($result->getMessages() as $message) {
                if (strpos($message['message'], 'Token is expired') === 0) {
                    // If expired is true, the rest of the token is valid, so we can refresh
                    $expired = true;
                    if (!empty($matches[1])) {
                        // We need a member, even if the result is false
                        $parser = new Parser();
                        $parsedToken = $parser->parse((string)$matches[1]);
                        /** @var Member $member */
                        $member = Member::get()
                            ->filter(['JWTUniqueID' => $parsedToken->getClaim('jti')])
                            ->byID($parsedToken->getClaim('uid'));
                    }
                }
            }
        } elseif ($member) {
            $expired = true;
        }

        if ($expired && $member) {
            $member->Token = $authenticator->generateToken($member);
        } else {
            // Everything is wrong, give an empty member without token
            $member = Member::create(['ID' => 0, 'FirstName' => 'Anonymous']);
        }
        // Maybe not _everything_, we possibly have an anonymous allowed user
        if ($member->ID === 0 && JWTAuthenticator::config()->get('anonymous_allowed')) {
            $member->Token = $authenticator->generateToken($member);
        }

        return $member;
    }
}
