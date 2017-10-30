<?php

namespace Firesphere\GraphQLJWT\tests;

use Firesphere\GraphQLJWT\CreateTokenMutationCreator;
use Firesphere\GraphQLJWT\JWTAuthenticator;
use Firesphere\GraphQLJWT\ValidateTokenQueryCreator;
use GraphQL\Type\Definition\ResolveInfo;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\Session;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;

class ValidateTokenQueryCreatorTest extends SapphireTest
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

    private function buildRequest()
    {
        $request = new HTTPRequest('POST', Director::absoluteBaseURL() . '/graphql');
        $request->addHeader('Authorization', 'Bearer ' . $this->token);

        $request->setSession(new Session(['hello' => 'bye'])); // We need a session
        Controller::curr()->setRequest($request);

        return $request;
    }

    public function testValidateToken()
    {
        $this->buildRequest();

        $queryCreator = Injector::inst()->get(ValidateTokenQueryCreator::class);
        $response = $queryCreator->resolve(null, [], [], new ResolveInfo([]));

        $this->assertTrue($response['Valid']);
    }

    public function testExpiredToken()
    {
        Config::modify()->set(JWTAuthenticator::class, 'nbf_expiration', -5);

        $createToken = Injector::inst()->get(CreateTokenMutationCreator::class);

        $response = $createToken->resolve(
            null,
            ['Email' => 'admin@silverstripe.com', 'Password' => 'error'],
            [],
            new ResolveInfo([])
        );
        $this->token = $response->Token;

        $this->buildRequest();

        $queryCreator = Injector::inst()->get(ValidateTokenQueryCreator::class);
        $response = $queryCreator->resolve(null, [], [], new ResolveInfo([]));

        $this->assertFalse($response['Valid']);
        $this->assertContains('Token is expired', $response['Message']);
    }
}
