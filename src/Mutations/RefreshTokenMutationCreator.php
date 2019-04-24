<?php declare(strict_types=1);

namespace Firesphere\GraphQLJWT\Mutations;

use App\Users\GraphQL\Types\TokenStatusEnum;
use BadMethodCallException;
use Exception;
use Firesphere\GraphQLJWT\Helpers\HeaderExtractor;
use Firesphere\GraphQLJWT\Helpers\MemberTokenGenerator;
use Firesphere\GraphQLJWT\Helpers\RequiresAuthenticator;
use Firesphere\GraphQLJWT\Model\JWTRecord;
use GraphQL\Type\Definition\ResolveInfo;
use GraphQL\Type\Definition\Type;
use OutOfBoundsException;
use Psr\Container\NotFoundExceptionInterface;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Extensible;
use SilverStripe\GraphQL\MutationCreator;
use SilverStripe\GraphQL\OperationResolver;
use SilverStripe\ORM\ValidationException;

class RefreshTokenMutationCreator extends MutationCreator implements OperationResolver
{
    use RequiresAuthenticator;
    use HeaderExtractor;
    use MemberTokenGenerator;
    use Extensible;

    public function attributes(): array
    {
        return [
            'name'        => 'refreshToken',
            'description' => 'Refreshes a JWT token for a valid user. To be done'
        ];
    }

    public function type(): Type
    {
        return $this->manager->getType('MemberToken');
    }

    /**
     * @param mixed $object
     * @param array $args
     * @param mixed $context
     * @param ResolveInfo $info
     * @return array
     * @throws NotFoundExceptionInterface
     * @throws ValidationException
     * @throws BadMethodCallException
     * @throws OutOfBoundsException
     * @throws Exception
     */
    public function resolve($object, array $args, $context, ResolveInfo $info): array
    {
        $authenticator = $this->getJWTAuthenticator();
        $request = Controller::curr()->getRequest();
        $token = $this->getAuthorizationHeader($request);

        // Check status of existing token
        /** @var JWTRecord $record */
        list($record, $status) = $authenticator->validateToken($token, $request);
        $member = null;
        switch ($status) {
            case TokenStatusEnum::STATUS_OK:
            case TokenStatusEnum::STATUS_EXPIRED:
                $member = $record->Member();
                $renewable = true;
                break;
            case TokenStatusEnum::STATUS_DEAD:
            case TokenStatusEnum::STATUS_INVALID:
            default:
                $member = null;
                $renewable = false;
                break;
        }

        // Check if renewable
        if (!$renewable) {
            return $this->generateResponse($status);
        }

        // Create new token for member
        $newToken = $authenticator->generateToken($request, $member);
        return $this->generateResponse(TokenStatusEnum::STATUS_OK, $member, $newToken->__toString());
    }
}
