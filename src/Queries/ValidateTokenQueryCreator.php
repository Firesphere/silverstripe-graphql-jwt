<?php

namespace Firesphere\GraphQLJWT\Queries;

use App\Users\GraphQL\Types\TokenStatusEnum;
use BadMethodCallException;
use Exception;
use Firesphere\GraphQLJWT\Authentication\JWTAuthenticator;
use Firesphere\GraphQLJWT\Helpers\GeneratesTokenOutput;
use Firesphere\GraphQLJWT\Helpers\HeaderExtractor;
use Firesphere\GraphQLJWT\Helpers\RequiresAuthenticator;
use Firesphere\GraphQLJWT\Model\JWTRecord;
use GraphQL\Type\Definition\ResolveInfo;
use OutOfBoundsException;
use Psr\Container\NotFoundExceptionInterface;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\GraphQL\OperationResolver;
use SilverStripe\GraphQL\QueryCreator;

class ValidateTokenQueryCreator extends QueryCreator implements OperationResolver
{
    use RequiresAuthenticator;
    use HeaderExtractor;
    use GeneratesTokenOutput;

    public function attributes()
    {
        return [
            'name'        => 'validateToken',
            'description' => 'Validates a given token from the Bearer header'
        ];
    }

    public function args()
    {
        return [];
    }

    public function type()
    {
        return $this->manager->getType('MemberToken');
    }

    /**
     * @param mixed       $object
     * @param array       $args
     * @param mixed       $context
     * @param ResolveInfo $info
     * @return array
     * @throws NotFoundExceptionInterface
     * @throws OutOfBoundsException
     * @throws BadMethodCallException
     * @throws HTTPResponse_Exception
     * @throws Exception
     */
    public function resolve($object, array $args, $context, ResolveInfo $info)
    {
        /** @var JWTAuthenticator $authenticator */
        $authenticator = $this->getJWTAuthenticator();
        $request = Controller::curr()->getRequest();
        $token = $this->getAuthorizationHeader($request);

        /** @var JWTRecord $record */
        list($record, $status) = $authenticator->validateToken($token, $request);
        $member = $status === TokenStatusEnum::STATUS_OK ? $record->Member() : null;
        return $this->generateResponse($status, $member, $token);
    }
}
