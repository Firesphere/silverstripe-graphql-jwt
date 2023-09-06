<?php

namespace Firesphere\GraphQLJWT\Tests;

use Exception;
use Firesphere\GraphQLJWT\Authentication\JWTAuthenticationHandler;
use Firesphere\GraphQLJWT\Mutations\CreateTokenMutationCreator;
use Firesphere\GraphQLJWT\Resolvers\Resolver;
use GraphQL\Type\Definition\ResolveInfo;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Environment;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Security\Member;

class JWTAuthenticationHandlerTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/JWTAuthenticatorTest.yml';

    protected $member;

    protected $token;

    protected function setUp(): void
    {
        Controller::curr()->getRequest()->addHeader('Origin', 'GraphQLJWT_Test');
        Environment::putEnv('JWT_SIGNER_KEY=a_256bits_test_signer_or_it_would_not_work_correctly');

        parent::setUp();
        $this->member = $this->objFromFixture(Member::class, 'admin');
        $response = Resolver::resolveCreateToken(
            null,
            ['email' => 'admin@silverstripe.com', 'password' => 'error'],
        );

        $this->token = $response['token'];
    }

    /**
     * @throws Exception
     */
    public function testInvalidAuthenticateRequest()
    {
        Environment::putEnv('JWT_SIGNER_KEY=a_long_long_long_long_long_long_long_long_long_string');

        $request = clone Controller::curr()->getRequest();
        $request->addHeader('Authorization', 'Bearer ' . $this->token);

        $handler = JWTAuthenticationHandler::singleton();

        $result = $handler->authenticateRequest($request);
        Environment::putEnv('JWT_SIGNER_KEY=a_256bits_test_signer_or_it_would_not_work_correctly');

        $this->assertNull($result);
    }

    /**
     * @throws Exception
     */
    public function testAuthenticateRequest()
    {
        $request = clone Controller::curr()->getRequest();
        $request->addHeader('Authorization', 'Bearer ' . $this->token);

        $handler = JWTAuthenticationHandler::singleton();

        $result = $handler->authenticateRequest($request);
        $this->assertInstanceOf(Member::class, $result);
        $this->assertTrue($result->isInDB());
    }
}
