<?php

namespace Firesphere\GraphQLJWT\Tests;

use Firesphere\GraphQLJWT\Authentication\AnonymousUserAuthenticator;
use Firesphere\GraphQLJWT\Authentication\CustomAuthenticatorRegistry;
use Firesphere\GraphQLJWT\Authentication\JWTAuthenticator;
use Firesphere\GraphQLJWT\Resolvers\Resolver;
use GraphQL\Type\Definition\ResolveInfo;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Session;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Security\Member;

class RefreshTokenTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/JWTAuthenticatorTest.yml';

    protected $member;

    protected $token;

    protected $anonymousToken;

    public function setUp()
    {
        Environment::setENv('JWT_SIGNER_KEY', 'test_signer');

        parent::setUp();
        $this->member = $this->objFromFixture(Member::class, 'admin');

        // Enable anonymous authentication for this test
        Injector::inst()->get(CustomAuthenticatorRegistry::class)
            ->setCustomAuthenticators([AnonymousUserAuthenticator::singleton()]);

        // Requires to be an expired token
        Config::modify()->set(JWTAuthenticator::class, 'nbf_expiration', -5);

        // Normal token
        $response = Resolver::resolveCreateToken(
            null,
            ['email' => 'admin@silverstripe.com', 'password' => 'error']
        );
        $this->token = $response['token'];

        // Anonymous token
        $response = Resolver::resolveCreateToken(
            null,
            ['email' => 'anonymous']
        );
        $this->anonymousToken = $response['token'];
    }

    public function tearDown()
    {
        parent::tearDown();
    }

    private function buildRequest($anonymous = false)
    {
        $token = $anonymous ? $this->anonymousToken : $this->token;
        $request = clone Controller::curr()->getRequest();
        $request->addHeader('Authorization', 'Bearer ' . $token);

        $request->setSession(new Session(['hello' => 'bye'])); // We need a session
        Controller::curr()->setRequest($request);

        return $request;
    }

    public function testRefreshToken()
    {
        $this->buildRequest();

        $response = Resolver::resolveRefreshToken();

        $this->assertNotNull($response['token']);
        $this->assertInstanceOf(Member::class, $response['member']);
    }

    public function testAnonRefreshToken()
    {
        $this->buildRequest(true);

        $response = Resolver::resolveRefreshToken();

        $this->assertNotNull($response['token']);
        $this->assertInstanceOf(Member::class, $response['member']);
    }
}
