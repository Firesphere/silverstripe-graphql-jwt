<?php

namespace Firesphere\GraphQLJWT\tests;


use Firesphere\GraphQLJWT\CreateTokenMutationCreator;
use Firesphere\GraphQLJWT\JWTAuthenticationHandler;
use Firesphere\GraphQLJWT\JWTAuthenticator;
use GraphQL\Type\Definition\ResolveInfo;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Config;
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
        parent::setUp();
        $this->member = $this->objFromFixture(Member::class, 'admin');
        $createToken = Injector::inst()->get(CreateTokenMutationCreator::class);

        $response = $createToken->resolve(
            null, ['Email' => 'admin@silverstripe.com', 'Password' => 'error'], [],
            new ResolveInfo([])
        );

        $this->token = $response->Token;
    }

    public function tearDown()
    {
        parent::tearDown();
    }

    public function testAuthenticateRequest()
    {
        $request = new HTTPRequest('POST', Director::absoluteBaseURL() . '/graphql');
        $request->addHeader('Authorization', 'Bearer ' . $this->token);

        $handler = Injector::inst()->get(JWTAuthenticationHandler::class);

        $result = $handler->authenticateRequest($request);

        $this->assertTrue($result instanceof Member);
    }

    public function testInvalidAuthenticateRequest()
    {
        Config::modify()->set(JWTAuthenticator::class, 'signer_key', 'string');

        $request = new HTTPRequest('POST', Director::absoluteBaseURL() . '/graphql');
        $request->addHeader('Authorization', 'Bearer ' . $this->token);

        $handler = Injector::inst()->get(JWTAuthenticationHandler::class);

        $result = $handler->authenticateRequest($request);

        $this->assertTrue($result instanceof Member);

    }
}
