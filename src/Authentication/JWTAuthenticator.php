<?php

namespace Firesphere\GraphQLJWT;

use BadMethodCallException;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\GraphQL\Controller;
use SilverStripe\ORM\ValidationException;
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
     * @throws \OutOfBoundsException
     * @throws \BadMethodCallException
     */
    public function authenticate(array $data, HTTPRequest $request, ValidationResult &$result = null)
    {
        if (!$result) {
            $result = new ValidationResult();
        }
        $token = $data['token'];

        return $this->validateToken($token, $result);
    }

    /**
     * @param Member $member
     * @return Token
     * @throws ValidationException
     * @throws BadMethodCallException
     */
    public function generateToken(Member $member)
    {
        $config = static::config();
        $signer = new Sha256();
        $uniqueID = uniqid(getenv('JWT_PREFIX'), true);

        $request = Controller::curr()->getRequest();
        $audience = $request->getHeader('Origin');
        $signerKey = getenv('JWT_SIGNER_KEY');

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

        // Save the member if it's not anonymous
        if ($member->ID > 0) {
            $member->JWTUniqueID = $uniqueID;
            $member->write();
        }

        // Return the token
        return $token->getToken();
    }

    /**
     * @param string $token
     * @param ValidationResult $result
     * @return null|Member
     * @throws \OutOfBoundsException
     * @throws \BadMethodCallException
     */
    private function validateToken($token, &$result)
    {
        $parser = new Parser();
        $parsedToken = $parser->parse((string)$token);
        $signer = new Sha256();
        $signerKey = getenv('JWT_SIGNER_KEY');
        $member = null;

        // If the token is not verified, just give up
        if (!$parsedToken->verify($signer, $signerKey)) {
            $result->addError('Invalid token');
        }
        // An expired token can be renewed
        elseif ($parsedToken->isExpired()) {
            $result->addError('Token is expired, please renew your token with a refreshToken query');
        }
        // Everything seems fine, let's find a user
        elseif ($parsedToken->getClaim('uid') > 0 && $parsedToken->getClaim('jti')) {
            /** @var Member $member */
            $member = Member::get()
                ->filter(['JWTUniqueID' => $parsedToken->getClaim('jti')])
                ->byID($parsedToken->getClaim('uid'));
        }
        // Not entirely fine, do we allow anonymous users?
        // Then, if the token is valid, return an anonymous user
        if (
            $result->isValid() &&
            $parsedToken->getClaim('uid') === 0 &&
            static::config()->get('anonymous_allowed')
        ) {
            $member = Member::create(['ID' => 0, 'FirstName' => 'Anonymous']);
        }

        return $result->isValid() ? $member : null;

    }
}
