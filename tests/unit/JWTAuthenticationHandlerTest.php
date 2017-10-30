<?php

namespace Firesphere\GraphQLJWT\tests;

use Firesphere\GraphQLJWT\CreateTokenMutationCreator;
use Firesphere\GraphQLJWT\JWTAuthenticationHandler;
use GraphQL\Type\Definition\ResolveInfo;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;

class JWTAuthenticationHandlerTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/JWTAuthenticatorTest.yml';

    protected $member;

    protected $token;

    public function setUp()
    {
        Environment::putEnv('JWT_SIGNER_KEY=test_signer');

        parent::setUp();
        $this->member = $this->objFromFixture(Member::class, 'admin');
        $createToken = Injector::inst()->get(CreateTokenMutationCreator::class);

        $response = $createToken->resolve(
            null,
            ['Email' => 'admin@silverstripe.com', 'Password' => 'error'],
            [],
            new ResolveInfo([])
        );

        $this->token = $response->Token;
    }

    public function tearDown()
    {
        parent::tearDown();
    }

    public function testInvalidAuthenticateRequest()
    {
        Environment::putEnv('JWT_SIGNER_KEY=string');

        $request = new HTTPRequest('POST', Director::absoluteBaseURL() . '/graphql');
        $request->addHeader('Authorization', 'Bearer ' . $this->token);

        $handler = Injector::inst()->get(JWTAuthenticationHandler::class);

        $result = $handler->authenticateRequest($request);
        Environment::putEnv('JWT_SIGNER_KEY=test_signer');

        $this->assertNull($result);
    }

    public function testAuthenticateRequest()
    {
        $request = new HTTPRequest('POST', Director::absoluteBaseURL() . '/graphql');
        $request->addHeader('Authorization', 'Bearer ' . $this->token);

        $handler = Injector::inst()->get(JWTAuthenticationHandler::class);

        $result = $handler->authenticateRequest($request);

        $this->assertInstanceOf(Member::class, $result);
        $this->assertGreaterThan(0, $result->ID);
    }
}
