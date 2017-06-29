<?php

namespace Firesphere\GraphQLJWT;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;

class JWTAuthenticator extends MemberAuthenticator
{

    public function supportedServices()
    {
        return Authenticator::LOGIN | Authenticator::LOGOUT | Authenticator::CMS_LOGIN;
    }

    /**
     * @param array $data
     * @param HTTPRequest $request
     * @param ValidationResult|null $result
     * @return Member|null
     */
    public function authenticate(array $data, HTTPRequest $request, ValidationResult &$result = null)
    {
        if(!$result) {
            $result = new ValidationResult();
        }
        $token = $data['token'];
        $parsedToken = (new Parser())->parse((string) $token);
        $signer = new Sha256();

        if(!$parsedToken->verify($signer, 'silverstripe-jwt')) {
            $result->addError('Invalid token');
            return null;
        }
        return Member::get()->byID($parsedToken->getClaim('uid'));
    }

    public function generateToken(Member $member)
    {
        $signer = new Sha256();

        $token = (new Builder())->setIssuer(Director::absoluteBaseURL())// Configures the issuer (iss claim)
            ->setAudience(Director::absoluteBaseURL())// Configures the audience (aud claim)
            ->setId(uniqid('jwt_', true), true)// Configures the id (jti claim), replicating as a header item
            ->setIssuedAt(time())// Configures the time that the token was issue (iat claim)
            ->setNotBefore(time() + 60)// Configures the time that the token can be used (nbf claim)
            ->setExpiration(time() + 3600)// Configures the expiration time of the token (nbf claim)
            ->set('uid', $member->ID)// Configures a new claim, called "uid"
            ->sign($signer, 'silverstripe-jwt')
            ->getToken(); // Retrieves the generated token

        return $token;
    }
}
