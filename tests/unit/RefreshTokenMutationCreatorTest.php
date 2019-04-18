<?php

namespace Firesphere\GraphQLJWT\Tests;

use Firesphere\GraphQLJWT\Authentication\AnonymousUserAuthenticator;
use Firesphere\GraphQLJWT\Authentication\JWTAuthenticator;
use Firesphere\GraphQLJWT\Mutations\CreateTokenMutationCreator;
use Firesphere\GraphQLJWT\Mutations\RefreshTokenMutationCreator;
use GraphQL\Type\Definition\ResolveInfo;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Session;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Security\Member;

class RefreshTokenMutationCreatorTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/JWTAuthenticatorTest.yml';

    protected $member;

    protected $token;

    protected $anonymousToken;

    /**
     * @throws ValidationException
     */
    public function setUp()
    {
        Environment::setENv('JWT_SIGNER_KEY', 'test_signer');

        parent::setUp();
        $this->member = $this->objFromFixture(Member::class, 'admin');

        // Enable anonymous authentication for this test
        $createToken = CreateTokenMutationCreator::singleton();
        $createToken->setCustomAuthenticators([AnonymousUserAuthenticator::singleton()]);

        // Requires to be an expired token
        Config::modify()->set(JWTAuthenticator::class, 'nbf_expiration', -5);

        // Normal token
        $response = $createToken->resolve(
            null,
            ['Email' => 'admin@silverstripe.com', 'Password' => 'error'],
            [],
            new ResolveInfo([])
        );
        $this->token = $response['Token'];

        // Anonymous token
        $response = $createToken->resolve(
            null,
            ['Email' => 'anonymous'],
            [],
            new ResolveInfo([])
        );
        $this->anonymousToken = $response['Token'];
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

        $queryCreator = Injector::inst()->get(RefreshTokenMutationCreator::class);
        $response = $queryCreator->resolve(null, [], [], new ResolveInfo([]));

        $this->assertNotNull($response['Token']);
        $this->assertInstanceOf(Member::class, $response['Member']);
    }

    public function testAnonRefreshToken()
    {
        $this->buildRequest(true);

        $queryCreator = Injector::inst()->get(RefreshTokenMutationCreator::class);
        $response = $queryCreator->resolve(null, [], [], new ResolveInfo([]));

        $this->assertNotNull($response['Token']);
        $this->assertInstanceOf(Member::class, $response['Member']);
    }
}
