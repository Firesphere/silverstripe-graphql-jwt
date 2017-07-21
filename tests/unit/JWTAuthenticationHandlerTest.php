<?php

namespace Firesphere\GraphQLJWT\tests;

use Firesphere\GraphQLJWT\CreateTokenMutationCreator;
use Firesphere\GraphQLJWT\JWTAuthenticationHandler;
use Firesphere\GraphQLJWT\JWTAuthenticator;
use GraphQL\Type\Definition\ResolveInfo;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\Session;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;

class JWTAuthenticationHandlerTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/JWTAuthenticatorTest.yml';

    protected $member;

    protected $request;

    public function setUp()
    {
        parent::setUp();
        $this->member = $this->objFromFixture(Member::class, 'admin');
        $createToken = Injector::inst()->get(CreateTokenMutationCreator::class);

        $response = $createToken->resolve(
            null,
            ['Email' => 'admin@silverstripe.com', 'Password' => 'error'],
            [],
            new ResolveInfo([])
        );

        $this->request = new HTTPRequest('POST', Director::absoluteBaseURL() . '/graphql');
        $this->request->addHeader('Authorization', 'Bearer ' . $response->token);
        $this->request->setSession(new Session(['test' => 'value'])); // We need a session
    }

    public function tearDown()
    {
        parent::tearDown();
    }

    public function testAuthenticateRequest()
    {
        $handler = Injector::inst()->get(JWTAuthenticationHandler::class);

        $result = $handler->authenticateRequest($this->request);

        $this->assertTrue($result instanceof Member);
    }

    public function testInvalidAuthenticateRequest()
    {
        Config::modify()->set(JWTAuthenticator::class, 'signer_key', 'string');

        $handler = Injector::inst()->get(JWTAuthenticationHandler::class);

        $result = $handler->authenticateRequest($this->request);

        $this->assertTrue($result instanceof Member);
    }
}
