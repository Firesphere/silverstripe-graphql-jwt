<?php

declare(strict_types=1);

namespace Firesphere\GraphQLJWT\Authentication;
// This is needed since a deeply buried method in jwt token library uses this timezone
date_default_timezone_set('Etc/GMT+0');

use BadMethodCallException;
use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use Exception;
use Firesphere\GraphQLJWT\Extensions\MemberExtension;
use Firesphere\GraphQLJWT\Helpers\ErrorMessageGenerator;
use Firesphere\GraphQLJWT\Helpers\MemberTokenGenerator;
use Firesphere\GraphQLJWT\Model\JWTRecord;
use Firesphere\GraphQLJWT\Resolvers\Resolver;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use LogicException;
use OutOfBoundsException;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\ORM\ValidationException;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;
use SilverStripe\Security\Permission;

class JWTAuthenticator extends MemberAuthenticator
{
    use Injectable;
    use Configurable;
    use MemberTokenGenerator;

    const JWT_SIGNER_KEY = 'JWT_SIGNER_KEY';

    const JWT_KEY_PASSWORD = 'JWT_KEY_PASSWORD';

    const JWT_PUBLIC_KEY = 'JWT_PUBLIC_KEY';

    /**
     * Key is RSA public/private pair
     */
    const RSA = 'RSA';

    /**
     * Key is RSA public/private pair, with password enabled
     */
    const RSA_PASSWORD = 'RSA_PASSWORD';

    /**
     * Key is HMAC string
     */
    const HMAC = 'HMAC';

    /**
     * Set to true to allow anonymous JWT tokens (no member record / email / password)
     *
     * @config
     * @var bool
     */
    private static $anonymous_allowed = false;

    /**
     * @config
     * @var int
     */
    private static $nbf_time = 0;

    /**
     * Expires after 1 hour
     *
     * @config
     * @var int
     */
    private static $nbf_expiration = 3600;

    /**
     * Expires after 1 hour
     *
     * @config
     * @var int
     */
    private static $nbf_signup_expiration = 3600;

    /**
     * Expires after 1 hour
     *
     * @config
     * @var int
     */
    private static $nbf_reset_expiration = 3600;

    /**
     * Token can be refreshed within 7 days
     *
     * @config
     * @var int
     */
    private static $nbf_refresh_expiration = 604800;

    /**
     * @config
     * @var Config
     */
    private $config;

    public function __construct(Configuration $config = null)
    {

        $this->config = $config ?? Configuration::forSymmetricSigner($this->getSigner(), $this->getPrivateKey());
    }

    /**
     * Keys are one of:
     *   - public / private RSA pair files
     *   - public / private RSA pair files, password protected private key
     *   - private HMAC string
     *
     * @return string
     */

    protected function getKeyType(): string
    {
        $signerKey = $this->getEnv(self::JWT_SIGNER_KEY);
        $path = $this->resolvePath($signerKey);
        if (!$path) {
            return self::HMAC;
        }
        if ($this->getEnv(self::JWT_KEY_PASSWORD, null)) {
            return self::RSA_PASSWORD;
        }
        return self::RSA;
    }

    /**
     * @return Signer
     */
    protected function getSigner(): Signer
    {
        switch ($this->getKeyType()) {
            case self::HMAC:
                return new Hmac\Sha256();
            case self::RSA:
            case self::RSA_PASSWORD:
            default:
                return new Rsa\Sha256();
        }
    }

    /**
     * Get private key used to generate JWT tokens
     *
     * @return Key
     */
    protected function getPrivateKey(): Key
    {
        // Note: Only private key has password enabled
        $password = $this->getEnv(self::JWT_KEY_PASSWORD, null);
        return $this->makeKey(self::JWT_SIGNER_KEY, $password);
    }

    /**
     * Get public key used to validate JWT tokens
     *
     * @return Key
     * @throws LogicException
     */
    protected function getPublicKey(): Key
    {
        switch ($this->getKeyType()) {
            case self::HMAC:
                // If signer key is a HMAC string instead of a path, public key == private key
                return $this->getPrivateKey();
            default:
                // If signer key is a path to RSA token, then we require a separate public key path
                return $this->makeKey(self::JWT_PUBLIC_KEY);
        }
    }

    /**
     * Construct a new key from the named config variable
     *
     * @param string $name Key name
     * @param string|null $password Optional password
     * @return Key
     */
    private function makeKey(string $name, string $password = null): Key
    {
        $key = $this->getEnv($name);
        $path = $this->resolvePath($key);

        // String key
        if (empty($path)) {
            return InMemory::plainText($key);
        }

        // Build key from path
        return InMemory::file('file://' . $path, $password);
    }

    /**
     * JWT is stateless, therefore, we don't support anything but login
     *
     * @return int
     */
    public function supportedServices(): int
    {
        return Authenticator::LOGIN;
    }

    /**
     * @param array $data
     * @param HTTPRequest $request
     * @param ValidationResult|null $result
     * @return Member|null
     * @throws OutOfBoundsException
     * @throws BadMethodCallException
     * @throws Exception
     */
    public function authenticate(array $data, HTTPRequest $request, ValidationResult &$result = null): ?Member
    {
        if (!$result) {
            $result = new ValidationResult();
        }
        $token = $data['token'];

        /** @var JWTRecord $record */
        list($record, $status) = $this->validateToken($token, $request);

        $member = $record ? $record->Member() : null;

        if ($member && (!Permission::checkMember($member, 'ADMIN') && !$member->isActivated)) {
            $result->addError(
                _t('JWT.STATUS_INACTIVATED_USER', 'User is not activated. Please check your email for the activation link or request a new one.'),
                Resolver::STATUS_INACTIVATED_USER,
                $status
            );
            return null;
        }

        // Report success!
        if ($status === Resolver::STATUS_OK) {
            return $record->Member();
        }

        // Add errors to result
        $result->addError(
            ErrorMessageGenerator::getErrorMessage($status),
            ValidationResult::TYPE_ERROR,
            $status
        );

        return null;
    }

    /**
     * Generate a new JWT token for a given request, and optional (if anonymous_allowed) user
     *
     * @param HTTPRequest $request
     * @param Member|MemberExtension $member
     * @return Token
     * @throws ValidationException
     * @throws Exception
     */
    public function generateToken(HTTPRequest $request, Member $member): Token
    {
        $config = static::config();
        $uniqueID = uniqid($this->getEnv('JWT_PREFIX', ''), true);

        // Create new record
        $record = new JWTRecord();
        $record->UID = $uniqueID;
        $record->UserAgent = $request->getHeader('User-Agent');
        $record->Type = JWTRecord::TYPE_AUTH;
        $member->AuthTokens()->add($record);
        if (!$record->isInDB()) {
            $record->write();
        }

        // Get builder for this record
        $builder = $this->config->builder(ChainedFormatter::withUnixTimestampDates());


        foreach ($this->getAllowedDomains() as $domain) {
            $builder = $builder->permittedFor($domain);
        }

        $token = $builder
            // Configures the issuer (iss claim)
            ->issuedBy($request->getHeader('Origin'))
            // Configures the id (jti claim), replicating as a header item
            ->identifiedBy($uniqueID)->withHeader('jti', $uniqueID)
            // Configures the time that the token was issue (iat claim)
            ->issuedAt($this->getNow())
            // Configures the time that the token can be used (nbf claim)
            ->canOnlyBeUsedAfter($this->getNowPlus($config->get('nbf_time')))
            // Configures the expiration time of the token (nbf claim)
            ->expiresAt($this->getNowPlus($config->get('nbf_expiration')))
            // Set renew expiration (unix timestamp)
            ->withClaim('rexp', $this->getNowPlus($config->get('nbf_refresh_expiration')))
            // Configures a new claim, called "rid"
            ->withClaim('rid', $record->ID)
            // Set the subject, which is the member
            ->relatedTo($member->getJWTData())
            // Sign the key with the Signer's key
            ->getToken($this->config->signer(), $this->config->signingKey());

        // Return the token
        return $token;
    }

    /**
     * Generate a new JWT token for a given request, and optional (if anonymous_allowed) user
     *
     * @param HTTPRequest $request
     * @param string $email
     * @return Token
     * @throws ValidationException
     * @throws Exception
     */
    public function generateResetToken(HTTPRequest $request, Member $member): Token
    {
        $config = static::config();
        $uniqueID = uniqid($this->getEnv('JWT_PREFIX', ''), true);

        // Create new record
        $record = new JWTRecord();
        $record->UID = $uniqueID;
        $record->UserAgent = $request->getHeader('User-Agent');
        $record->Type = JWTRecord::TYPE_ANONYMOUS;

        if (!$record->isInDB()) {
            $record->write();
        }

        $member->ResetToken = $record;
        $member->write();

        // Get builder for this record
        $builder = $this->config->builder(ChainedFormatter::withUnixTimestampDates());

        foreach ($this->getAllowedDomains() as $domain) {
            $builder = $builder->permittedFor($domain);
        }

        $token = $builder
            // Configures the issuer (iss claim)
            ->issuedBy($request->getHeader('Origin'))
            // Configures the id (jti claim), replicating as a header item
            ->identifiedBy($uniqueID)->withHeader('jti', $uniqueID)
            // Configures the time that the token was issue (iat claim)
            ->issuedAt($this->getNow())
            // Configures the time that the token can be used (nbf claim)
            ->canOnlyBeUsedAfter($this->getNowPlus($config->get('nbf_time')))
            // Configures the expiration time of the token (nbf claim)
            ->expiresAt($this->getNowPlus($config->get('nbf_reset_expiration')))
            // Configures a new claim, called "rid"
            ->withClaim('rid', $record->ID)
            // Sign the key with the Signer's key
            ->getToken($this->config->signer(), $this->config->signingKey());

        // Return the token
        return $token;
    }

    /**
     * Generate a new user signup JWT token for a given request, and optional (if anonymous_allowed) user
     *
     * @param HTTPRequest $request
     * @param string $email
     * @return Token
     * @throws ValidationException
     * @throws Exception
     */
    public function generateSignupToken(HTTPRequest $request, Member $member): Token
    {
        $config = static::config();
        $uniqueID = uniqid($this->getEnv('JWT_PREFIX', ''), true);

        // Create new record
        $record = new JWTRecord();
        $record->UID = $uniqueID;
        $record->UserAgent = $request->getHeader('User-Agent');
        $record->Type = JWTRecord::TYPE_ANONYMOUS;

        if (!$record->isInDB()) {
            $record->write();
        }

        $member->SignupToken = $record;
        $member->write();

        // Get builder for this record
        $builder = $this->config->builder(ChainedFormatter::withUnixTimestampDates());

        foreach ($this->getAllowedDomains() as $domain) {
            $builder = $builder->permittedFor($domain);
        }

        $token = $builder
            // Configures the issuer (iss claim)
            ->issuedBy($request->getHeader('Origin'))
            // Configures the id (jti claim), replicating as a header item
            ->identifiedBy($uniqueID)->withHeader('jti', $uniqueID)
            // Configures the time that the token was issue (iat claim)
            ->issuedAt($this->getNow())
            // Configures the time that the token can be used (nbf claim)
            ->canOnlyBeUsedAfter($this->getNowPlus($config->get('nbf_time')))
            // Configures the expiration time of the token (nbf claim)
            ->expiresAt($this->getNowPlus($config->get('nbf_signup_expiration')))
            // Configures a new claim, called "rid"
            ->withClaim('rid', $record->ID)
            // Sign the key with the Signer's key
            ->getToken($this->config->signer(), $this->config->signingKey());

        // Return the token
        return $token;
    }

    /**
     * @param string $token
     * @param HTTPRequest $request
     * @return array|null Array with JWTRecord and int status (STATUS_*)
     * @throws BadMethodCallException|Exception
     */
    public function validateToken(?string $token, HTTPrequest $request): array
    {
        // Parse token
        $parsedToken = $this->parseToken($token);
        if (!$parsedToken) {
            return [null, Resolver::STATUS_INVALID];
        }

        // Find local record for this token
        /** @var JWTRecord $record */
        $record = JWTRecord::get()->byID($parsedToken->claims()->get('rid'));
        if (!$record) {
            return [null, Resolver::STATUS_INVALID];
        }

        // Check if token is reset-token
        if ($record->Type !== JWTRecord::TYPE_AUTH) {
            return [$record, Resolver::STATUS_INVALID];
        }

        if (!$record->Member()->isActivated) {
            return [$record, Resolver::STATUS_INACTIVATED_USER];
        }

        // Verified and valid = ok!
        $valid = $this->validateParsedToken($parsedToken, $request, $record);
        if ($valid) {
            return [$record, Resolver::STATUS_OK];
        }

        // If the token is invalid, but not because it has expired, fail
        if (!$parsedToken->isExpired($this->getNow())) {
            return [$record, Resolver::STATUS_INVALID];
        }

        // If expired, check if it can be renewed
        $canReniew = $this->canTokenBeRenewed($parsedToken);
        if ($canReniew) {
            return [$record, Resolver::STATUS_EXPIRED];
        }

        // If expired and cannot be renewed, it's dead
        return [$record, Resolver::STATUS_DEAD];
    }

    /**
     * @param string $token
     * @param HTTPRequest $request
     * @return array|null Array with JWTRecord and int status (STATUS_*)
     * @throws BadMethodCallException|Exception
     */
    public function validateAnonymousToken(?string $token, HTTPrequest $request): array
    {
        // Parse token
        $parsedToken = $this->parseToken($token);
        if (!$parsedToken) {
            return [null, Resolver::STATUS_INVALID];
        }

        // Find local record for this token
        /** @var JWTRecord $record */
        $record = JWTRecord::get()->byID($parsedToken->claims()->get('rid'));
        if (!$record) {
            return [null, Resolver::STATUS_INVALID];
        }

        // Check if token is reset-token
        if ($record->Type !== JWTRecord::TYPE_ANONYMOUS) {
            return [$record, Resolver::STATUS_INVALID];
        }

        // Verified and valid = ok!
        $valid = $this->validateParsedToken($parsedToken, $request, $record);
        if ($valid) {
            return [$record, Resolver::STATUS_OK];
        }

        // If the token is invalid, but not because it has expired, fail
        if (!$parsedToken->isExpired($this->getNow())) {
            return [$record, Resolver::STATUS_INVALID];
        }

        // If expired and cannot be renewed, it's dead
        return [$record, Resolver::STATUS_DEAD];
    }

    public function validateResetToken(?string $token, HTTPRequest $request): array
    {
        list($record, $status) = $this->validateAnonymousToken($token, $request);

        if ($status !== Resolver::STATUS_OK) {
            return [$record, $status];
        }
        $member = Member::get()->filter('ResetTokenID', $record->ID)->first();
        if (!$member) {
            return [$record, Resolver::STATUS_INVALID];
        }
        return [$record, Resolver::STATUS_OK];
    }

    public function validateSignupToken(?string $token, HTTPRequest $request): array
    {
        list($record, $status) = $this->validateAnonymousToken($token, $request);

        if ($status !== Resolver::STATUS_OK) {
            return [$record, $status];
        }
        $member = Member::get()->filter('SignupTokenID', $record->ID)->first();
        if (!$member) {
            return [$record, Resolver::STATUS_INVALID];
        }
        return [$record, Resolver::STATUS_OK];
    }

    /**
     * Parse a string into a token
     *
     * @param string|null $token
     * @return UnencryptedToken|null
     */
    protected function parseToken(?string $token): ?UnencryptedToken
    {
        // Ensure token given at all
        if (!$token) {
            return null;
        }

        try {
            // Verify parsed token matches signer
            $parser = $this->config->parser();
            $parsedToken = $parser->parse($token);
            return $parsedToken;
        } catch (Exception $ex) {
            // Un-parsable tokens are invalid
            return null;
        }
    }

    /**
     * Determine if the given token is current, given the context of the current request
     *
     * @param UnencryptedToken $parsedToken
     * @param HTTPRequest $request
     * @param JWTRecord $record
     * @return bool
     * @throws Exception
     */
    protected function validateParsedToken(UnencryptedToken $parsedToken, HTTPrequest $request, JWTRecord $record): bool
    {
        // @todo - upgrade
        // @see https://lcobucci-jwt.readthedocs.io/en/latest/upgrading/#replace-tokenverify-and-tokenvalidate-with-validation-api
        $this->config->setValidationConstraints(
            new IssuedBy($request->getHeader('Origin')),
            new PermittedFor(Director::absoluteBaseURL()),
            new IdentifiedBy($record->UID),
            new StrictValidAt(new SystemClock(new DateTimeZone(date_default_timezone_get()))),
        );

        $validator = $this->config->validator();
        return $validator->validate($parsedToken, ...$this->config->validationConstraints());
    }

    /**
     * Check if the given token can be renewed
     *
     * @param UnencryptedToken $parsedToken
     * @return bool
     * @throws Exception
     */
    protected function canTokenBeRenewed(UnencryptedToken $parsedToken): bool
    {
        $renewBefore = $parsedToken->claims()->get('rexp');
        return strtotime($renewBefore['date']) > $this->getNow()->getTimestamp();
    }

    /**
     * Return an absolute path from a relative one
     * If the path doesn't exist, returns null
     *
     * @param string $path
     * @param string $base
     * @return string|null
     */
    protected function resolvePath(string $path, string $base = BASE_PATH): ?string
    {
        if (strstr($path, '/') !== 0) {
            $path = $base . '/' . $path;
        }
        return realpath($path) ?: null;
    }


    /**
     * Get an environment value. If $default is not set and the environment isn't set either this will error.
     *
     * @param string $key
     * @param string|null $default
     * @return string|null
     * @throws LogicException Error if environment variable is required, but not configured
     */
    protected function getEnv(string $key, $default = null): ?string
    {
        $value = Environment::getEnv($key);
        if ($value) {
            return $value;
        }
        if (func_num_args() === 1) {
            throw new LogicException("Required environment variable {$key} not set");
        }
        return $default;
    }

    /**
     * @return DateTimeImmutable
     * @throws Exception
     */
    protected function getNow(): DateTimeImmutable
    {
        $clock = new SystemClock(new DateTimeZone(date_default_timezone_get()));
        return $clock->now();
    }

    /**
     * @param int $seconds
     * @return DateTimeImmutable
     * @throws Exception
     */
    protected function getNowPlus($seconds)
    {
        return $this->getNow()->add(new DateInterval(sprintf("PT%dS", $seconds)));
    }

    protected function getAllowedDomains(): array
    {
        return $this->config()->get('signer_domains');
    }
}
