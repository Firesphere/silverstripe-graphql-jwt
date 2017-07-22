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

    /**
     * JWT is stateless, therefore, we don't support anything but login
     *
     * @return int
     */
    public function supportedServices()
    {
        return Authenticator::LOGIN | Authenticator::CMS_LOGIN;
    }

    /**
     * @param array $data
     * @param HTTPRequest $request
     * @param ValidationResult|null $result
     * @return Member|null
     * @throws \BadMethodCallException
     * @throws \OutOfBoundsException
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
        $member = null;

        if (!$parsedToken->verify($signer, $signerKey)) {
            $result->addError('Invalid token');
        }
        if ($parsedToken->isExpired()) {
            $result->addError('Token is expired, please renew your token with a refreshToken query');
        }
        if ($parsedToken->getClaim('uid')) {
            /** @var Member $member */
            $member = Member::get()->byID($parsedToken->getClaim('uid'));
        }

        return $result->isValid() ? $member : null;
    }

    /**
     * @param Member $member
     * @return \Lcobucci\JWT\Token
     * @throws \BadMethodCallException
     */
    public function generateToken(Member $member)
    {
        $config = static::config();
        $signer = new Sha256();
        $uniqueID = uniqid($config->get('prefix'), true);

        $request = Controller::curr()->getRequest();
        $audience = $request->getHeader('Origin');
        $signerKey = $config->get('signer_key');

        $builder = new Builder();
        $token = $builder
            // Configures the issuer (iss claim)
            ->setIssuer(Director::absoluteBaseURL())
            // Configures the audience (aud claim)
            ->setAudience($audience)
            // Configures the id (jti claim), replicating as a header item
            ->setId($uniqueID, true)
            // Configures the time that the token was issue (iat claim)
            ->setIssuedAt(time())
            // Configures the time that the token can be used (nbf claim)
            ->setNotBefore(time() + $config->get('nbf_time'))
            // Configures the expiration time of the token (nbf claim)
            ->setExpiration(time() + $config->get('nbf_expiration'))
            // Configures a new claim, called "uid"
            ->set('uid', $member->ID)
            // Sign the key with the Signer's key @todo: support certificates
            ->sign($signer, $signerKey);

        // Return the token
        return $token->getToken();
    }
}
