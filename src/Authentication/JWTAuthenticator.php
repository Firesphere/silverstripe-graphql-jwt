<?php

namespace Firesphere\GraphQLJWT\Authentication;

use BadMethodCallException;
use JWTException;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use OutOfBoundsException;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Environment;
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
     * @var Sha256|RsaSha256
     */
    private $signer;

    /**
     * @var string|Key;
     */
    private $privateKey;

    /**
     * @var string|Key;
     */
    private $publicKey;

    /**
     * JWTAuthenticator constructor.
     * @throws JWTException
     */
    public function __construct()
    {
        $key = Environment::getEnv('JWT_SIGNER_KEY');
        if (empty($key)) {
            throw new JWTException('No key defined!', 1);
        }
        $publicKeyLocation = Environment::getEnv('JWT_PUBLIC_KEY');
        if (file_exists($key) && !file_exists($publicKeyLocation)) {
            throw new JWTException('No public key found!', 1);
        }
    }

    /**
     * Setup the keys this has to be done on the spot for if the signer changes between validation cycles
     */
    private function setKeys()
    {
        $signerKey = Environment::getEnv('JWT_SIGNER_KEY');
        // If it's a private key, we also need a public key for validation!
        if (file_exists($signerKey)) {
            $this->signer = new RsaSha256();
            $password = Environment::getEnv('JWT_KEY_PASSWORD');
            $this->privateKey = new Key('file://' . $signerKey, $password ?: null);
            // We're having an RSA signed key instead of a string
            $this->publicKey = new Key('file://' . Environment::getEnv('JWT_PUBLIC_KEY'));
        } else {
            $this->signer = new Sha256();
            $this->privateKey = $signerKey;
            $this->publicKey = $signerKey;
        }
    }

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
     * @throws OutOfBoundsException
     * @throws BadMethodCallException
     */
    public function authenticate(array $data, HTTPRequest $request, ValidationResult &$result = null)
    {
        if (!$result) {
            $result = new ValidationResult();
        }
        $token = $data['token'];

        return $this->validateToken($token, $request, $result);
    }

    /**
     * @param Member $member
     * @return Token
     * @throws ValidationException
     * @throws BadMethodCallException
     */
    public function generateToken(Member $member)
    {
        $this->setKeys();
        $config = static::config();
        $uniqueID = uniqid(Environment::getEnv('JWT_PREFIX'), true);

        $request = Controller::curr()->getRequest();
        $audience = $request->getHeader('Origin');

        $builder = new Builder();
        $token = $builder
            // Configures the issuer (iss claim)
            ->setIssuer($audience)
            // Configures the audience (aud claim)
            ->setAudience(Director::absoluteBaseURL())
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
            // Set the subject, which is the member
            ->setSubject($member->getJWTData())
            // Sign the key with the Signer's key
            ->sign($this->signer, $this->privateKey);

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
     * @param HTTPRequest $request
     * @param ValidationResult $result
     * @return null|Member
     * @throws BadMethodCallException
     */
    private function validateToken($token, $request, &$result)
    {
        $this->setKeys();
        $parser = new Parser();
        $parsedToken = $parser->parse((string)$token);

        // Get a validator and the Member for this token
        list($validator, $member) = $this->getValidator($request, $parsedToken);

        $verified = $parsedToken->verify($this->signer, $this->publicKey);
        $valid = $parsedToken->validate($validator);

        // If the token is not verified, just give up
        if (!$verified || !$valid) {
            $result->addError('Invalid token');
        }
        // An expired token can be renewed
        if (
            $verified &&
            $parsedToken->isExpired()
        ) {
            $result->addError('Token is expired, please renew your token with a refreshToken query');
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

    /**
     * @param HTTPRequest $request
     * @param Token $parsedToken
     * @return array Contains a ValidationData and Member object
     * @throws OutOfBoundsException
     */
    private function getValidator($request, $parsedToken)
    {
        $audience = $request->getHeader('Origin');

        $member = null;
        $id = null;
        $validator = new ValidationData();
        $validator->setIssuer($audience);
        $validator->setAudience(Director::absoluteBaseURL());

        if ($parsedToken->getClaim('uid') === 0 && static::config()->get('anonymous_allowed')) {
            $id = $request->getSession()->get('jwt_uid');
        } elseif ($parsedToken->getClaim('uid') > 0) {
            $member = Member::get()->byID($parsedToken->getClaim('uid'));
            $id = $member->JWTUniqueID;
        }

        $validator->setId($id);

        return [$validator, $member];
    }
}
