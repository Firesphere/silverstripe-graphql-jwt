<?php declare(strict_types=1);

namespace Firesphere\GraphQLJWT\Authentication;

use App\Users\GraphQL\Types\TokenStatusEnum;
use BadMethodCallException;
use Exception;
use Firesphere\GraphQLJWT\Extensions\MemberExtension;
use Firesphere\GraphQLJWT\Helpers\MemberTokenGenerator;
use Firesphere\GraphQLJWT\Helpers\PathResolver;
use Firesphere\GraphQLJWT\Helpers\RequiresConfig;
use Firesphere\GraphQLJWT\Model\JWTRecord;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use LogicException;
use OutOfBoundsException;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\ORM\ValidationException;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;

class JWTAuthenticator extends MemberAuthenticator
{
    use Injectable;
    use Configurable;
    use RequiresConfig;
    use MemberTokenGenerator;

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
     * Token can be refreshed within 7 days
     *
     * @config
     * @var int
     */
    private static $nbf_refresh_expiration = 604800;

    /**
     * @return Signer
     */
    protected function getSigner(): Signer
    {
        $signerKey = $this->getEnv('JWT_SIGNER_KEY');
        if (PathResolver::resolve($signerKey)) {
            return new Rsa\Sha256();
        } else {
            return new Hmac\Sha256();
        }
    }

    /**
     * Get private key
     *
     * @return Key
     */
    protected function getPrivateKey(): Key
    {
        $signerKey = $this->getEnv('JWT_SIGNER_KEY');
        $signerPath = PathResolver::resolve($signerKey);
        if ($signerPath) {
            $password = $this->getEnv('JWT_KEY_PASSWORD', null);
            return new Key('file://' . $signerPath, $password);
        }
        return new Key($signerKey);
    }

    /**
     * Get public key
     *
     * @return Key
     * @throws LogicException
     */
    private function getPublicKey(): Key
    {
        $signerKey = Environment::getEnv('JWT_SIGNER_KEY');
        $signerPath = PathResolver::resolve($signerKey);
        // If it's a private key, we also need a public key for validation!
        if (empty($signerPath)) {
            return new Key($signerKey);
        }

        // Ensure public key exists
        $publicKey = Environment::getEnv('JWT_PUBLIC_KEY');
        $publicPath = PathResolver::resolve($publicKey);
        if (empty($publicPath)) {
            throw new LogicException('JWT_PUBLIC_KEY path does not exist');
        }
        return new Key('file://' . $publicPath);
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
     * @param array                 $data
     * @param HTTPRequest           $request
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

        // Report success!
        if ($status === TokenStatusEnum::STATUS_OK) {
            return $record->Member();
        }

        // Add errors to result
        $result->addError(
            $this->getErrorMessage($status),
            ValidationResult::TYPE_ERROR,
            $status
        );
        return null;
    }

    /**
     * Generate a new JWT token for a given request, and optional (if anonymous_allowed) user
     *
     * @param HTTPRequest            $request
     * @param Member|MemberExtension $member
     * @return Token
     * @throws ValidationException
     */
    public function generateToken(HTTPRequest $request, Member $member): Token
    {
        $config = static::config();
        $uniqueID = uniqid($this->getEnv('JWT_PREFIX', ''), true);

        // Create new record
        $record = new JWTRecord();
        $record->UID = $uniqueID;
        $record->UserAgent = $request->getHeader('User-Agent');
        $member->AuthTokens()->add($record);
        if (!$record->isInDB()) {
            $record->write();
        }

        // Create builder for this record
        $builder = new Builder();
        $now = DBDatetime::now()->getTimestamp();
        $token = $builder
            // Configures the issuer (iss claim)
            ->setIssuer($request->getHeader('Origin'))
            // Configures the audience (aud claim)
            ->setAudience(Director::absoluteBaseURL())
            // Configures the id (jti claim), replicating as a header item
            ->setId($uniqueID, true)
            // Configures the time that the token was issue (iat claim)
            ->setIssuedAt($now)
            // Configures the time that the token can be used (nbf claim)
            ->setNotBefore($now + $config->get('nbf_time'))
            // Configures the expiration time of the token (nbf claim)
            ->setExpiration($now + $config->get('nbf_expiration'))
            // Set renew expiration
            ->set('rexp', $now + $config->get('nbf_refresh_expiration'))
            // Configures a new claim, called "rid"
            ->set('rid', $record->ID)
            // Set the subject, which is the member
            ->setSubject($member->getJWTData())
            // Sign the key with the Signer's key
            ->sign($this->getSigner(), $this->getPrivateKey());

        // Return the token
        return $token->getToken();
    }

    /**
     * @param string      $token
     * @param HTTPRequest $request
     * @return array Array with JWTRecord and int status (STATUS_*)
     * @throws BadMethodCallException
     */
    public function validateToken(string $token, HTTPrequest $request): array
    {
        // Ensure token given at all
        if (!$token) {
            return [null, TokenStatusEnum::STATUS_INVALID];
        }

        // Parse token
        $parser = new Parser();
        try {
            $parsedToken = $parser->parse($token);
        } catch (Exception $ex) {
            // Un-parsable tokens are invalid
            return [null, TokenStatusEnum::STATUS_INVALID];
        }

        // Validate token against Id and user-agent
        $userAgent = $request->getHeader('User-Agent');
        /** @var JWTRecord $record */
        $record = JWTRecord::get()
            ->filter(['UserAgent' => $userAgent])
            ->byID($parsedToken->getClaim('rid'));
        if (!$record) {
            return [null, TokenStatusEnum::STATUS_INVALID];
        }

        // Get validator for this token
        $now = DBDatetime::now()->getTimestamp();
        $validator = new ValidationData();
        $validator->setIssuer($request->getHeader('Origin'));
        $validator->setAudience(Director::absoluteBaseURL());
        $validator->setId($record->UID);
        $validator->setCurrentTime($now);
        $verified = $parsedToken->verify($this->getSigner(), $this->getPublicKey());
        $valid = $parsedToken->validate($validator);

        // If unverified, break
        if (!$verified) {
            return [$record, TokenStatusEnum::STATUS_INVALID];
        }

        // Verified and valid = ok!
        if ($valid) {
            return [$record, TokenStatusEnum::STATUS_OK];
        }

        // If the token is invalid, but not because it has expired, fail
        if (!$parsedToken->isExpired()) {
            return [$record, TokenStatusEnum::STATUS_INVALID];
        }

        // If expired, check if it can be renewed
        $renewBefore = $parsedToken->getClaim('rexp');
        if ($renewBefore > $now) {
            return [$record, TokenStatusEnum::STATUS_EXPIRED];
        }

        // If expired and cannot be renewed, it's dead
        return [$record, TokenStatusEnum::STATUS_DEAD];
    }
}
