<?php declare(strict_types=1);

namespace Firesphere\GraphQLJWT\Mutations;

use App\Users\GraphQL\Types\TokenStatusEnum;
use Firesphere\GraphQLJWT\Extensions\MemberExtension;
use Firesphere\GraphQLJWT\Helpers\MemberTokenGenerator;
use Firesphere\GraphQLJWT\Helpers\RequiresAuthenticator;
use Generator;
use GraphQL\Type\Definition\ResolveInfo;
use GraphQL\Type\Definition\Type;
use Psr\Container\NotFoundExceptionInterface;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Extensible;
use SilverStripe\GraphQL\MutationCreator;
use SilverStripe\GraphQL\OperationResolver;
use SilverStripe\ORM\ValidationException;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

class CreateTokenMutationCreator extends MutationCreator implements OperationResolver
{
    use RequiresAuthenticator;
    use MemberTokenGenerator;
    use Extensible;

    /**
     * Extra authenticators to use for logging in with username / password
     *
     * @var Authenticator[]
     */
    protected $customAuthenticators = [];

    /**
     * @return Authenticator[]
     */
    public function getCustomAuthenticators(): array
    {
        return $this->customAuthenticators;
    }

    /**
     * @param Authenticator[] $authenticators
     * @return CreateTokenMutationCreator
     */
    public function setCustomAuthenticators(array $authenticators): self
    {
        $this->customAuthenticators = $authenticators;
        return $this;
    }

    public function attributes(): array
    {
        return [
            'name'        => 'createToken',
            'description' => 'Creates a JWT token for a valid user'
        ];
    }

    public function type(): Type
    {
        return $this->manager->getType('MemberToken');
    }

    public function args(): array
    {
        return [
            'Email'    => ['type' => Type::nonNull(Type::string())],
            'Password' => ['type' => Type::string()]
        ];
    }

    /**
     * @param mixed $object
     * @param array $args
     * @param mixed $context
     * @param ResolveInfo $info
     * @return array
     * @throws NotFoundExceptionInterface
     * @throws ValidationException
     */
    public function resolve($object, array $args, $context, ResolveInfo $info): array
    {
        // Authenticate this member
        $request = Controller::curr()->getRequest();
        $member = $this->getAuthenticatedMember($args, $request);

        // Handle unauthenticated
        if (!$member) {
            return $this->generateResponse(TokenStatusEnum::STATUS_BAD_LOGIN);
        }

        // Create new token from this member
        $authenticator = $this->getJWTAuthenticator();
        $token = $authenticator->generateToken($request, $member);
        return $this->generateResponse(TokenStatusEnum::STATUS_OK, $member, $token->__toString());
    }

    /**
     * Get an authenticated member from the given request
     *
     * @param array $args
     * @param HTTPRequest $request
     * @return Member|MemberExtension
     */
    protected function getAuthenticatedMember(array $args, HTTPRequest $request): ?Member
    {
        // Login with authenticators
        foreach ($this->getLoginAuthenticators() as $authenticator) {
            $result = ValidationResult::create();
            $member = $authenticator->authenticate($args, $request, $result);
            if ($member && $result->isValid()) {
                return $member;
            }
        }

        return null;
    }

    /**
     * Get any authenticator we should use for logging in users
     *
     * @return Authenticator[]|Generator
     */
    protected function getLoginAuthenticators(): Generator
    {
        // Check injected authenticators
        yield from $this->getCustomAuthenticators();

        // Get other login handlers from Security
        $security = Security::singleton();
        yield from $security->getApplicableAuthenticators(Authenticator::LOGIN);
    }
}
