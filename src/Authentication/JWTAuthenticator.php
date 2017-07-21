<?php

namespace Firesphere\GraphQLJWT;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\GraphQL\Controller;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;

class JWTAuthenticator extends MemberAuthenticator
{
    use Configurable;

    public function supportedServices()
    {
        return Authenticator::LOGIN | Authenticator::CMS_LOGIN;
    }

    /**
     * @param array                 $data
     * @param HTTPRequest           $request
     * @param ValidationResult|null $result
     * @return Member|null
     */
    public function authenticate(array $data, HTTPRequest $request, ValidationResult &$result = null)
    {
        if (!$result) {
            $result = new ValidationResult();
        }
        $token = $data['token'];
        $parser = new Parser();
        $parsedToken = $parser->parse((string)$token);
        $signer = new Sha256();
        $signerKey = static::config()->get('signer_key');

        if (!$parsedToken->verify($signer, $signerKey)) {
            $result->addError('Invalid token');

            return null;
        }
        /** @var Member $member */
        $member = Member::get()->byID($parsedToken->getClaim('uid'));

        return $member;
    }

    public function generateToken(Member $member)
    {
        $config = static::config();
        $signer = new Sha256();

        $audience = Controller::curr()->getRequest()->getHeader('Origin');

        $builder = new Builder();
        $token = $builder
            ->setIssuer(Director::absoluteBaseURL())// Configures the issuer (iss claim)
            ->setAudience($audience)// Configures the audience (aud claim)
            ->setId(uniqid($config->get('prefix'), true), true)// Configures the id (jti claim), replicating as a header item
            ->setIssuedAt(time())// Configures the time that the token was issue (iat claim)
            ->setNotBefore(time() + $config->get('nbf_time'))// Configures the time that the token can be used (nbf claim)
            ->setExpiration(time() + $config->get('nbf_expiration'))// Configures the expiration time of the token (nbf claim)
            ->set('uid', $member->ID)// Configures a new claim, called "uid"
            ->sign($signer, $config->get('signer_key'))
            ->getToken(); // Retrieves the generated token

        return $token;
    }
}
