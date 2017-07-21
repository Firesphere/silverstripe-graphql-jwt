<?php

namespace Firesphere\GraphQLJWT\Tests;


use Firesphere\GraphQLJWT\CreateTokenMutationCreator;
use Firesphere\GraphQLJWT\JWTAuthenticator;
use Firesphere\GraphQLJWT\RefreshTokenMutationCreator;
use GraphQL\Type\Definition\ResolveInfo;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\Session;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;

class RefreshTokenMutationCreatorTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/JWTAuthenticatorTest.yml';

    protected $member;

    public function setUp()
    {
        parent::setUp();
        $this->member = $this->objFromFixture(Member::class, 'admin');
        $createToken = Injector::inst()->get(CreateTokenMutationCreator::class);
        // Requires to be an expired token
        Config::modify()->set(JWTAuthenticator::class, 'nbf_expiration', -5);

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

    private function buildRequest()
    {
        $request = new HTTPRequest('POST', Director::absoluteBaseURL() . '/graphql');
        $request->addHeader('Authorization', 'Bearer ' . $this->token);

        $request->setSession(new Session(['hello' => 'bye'])); // We need a session
        Controller::curr()->setRequest($request);

        return $request;
    }

    public function testRefreshToken()
    {
        $this->buildRequest();

        $queryCreator = Injector::inst()->get(RefreshTokenMutationCreator::class);
        $response = $queryCreator->resolve(null, [], [], new ResolveInfo([]));

        $this->assertNotNull($response->Token);
        $this->assertTrue($response instanceof Member);

    }
}