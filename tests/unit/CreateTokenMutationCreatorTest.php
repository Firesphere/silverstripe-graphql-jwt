<?php

namespace Firesphere\GraphQLJWT\Tests;

use Firesphere\GraphQLJWT\Authentication\AnonymousUserAuthenticator;
use Firesphere\GraphQLJWT\Mutations\CreateTokenMutationCreator;
use GraphQL\Type\Definition\ResolveInfo;
use SilverStripe\Core\Environment;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Security\Member;

class CreateTokenMutationCreatorTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/JWTAuthenticatorTest.yml';

    protected $member;

    public function setUp()
    {
        Environment::putEnv('JWT_SIGNER_KEY=test_signer');

        parent::setUp();
        $this->member = $this->objFromFixture(Member::class, 'admin');
    }

    /**
     * @throws ValidationException
     */
    public function testResolveValid()
    {
        $createToken = CreateTokenMutationCreator::singleton();

        $response = $createToken->resolve(
            null,
            ['Email' => 'admin@silverstripe.com', 'Password' => 'error'],
            [],
            new ResolveInfo([])
        );

        $this->assertTrue($response['Member'] instanceof Member);
        $this->assertNotNull($response['Token']);
    }

    /**
     * @throws ValidationException
     */
    public function testResolveInvalidWithAllowedAnonymous()
    {
        $authenticator = CreateTokenMutationCreator::singleton();

        // Inject custom authenticator
        $authenticator->setCustomAuthenticators([
            AnonymousUserAuthenticator::singleton(),
        ]);

        $response = $authenticator->resolve(
            null,
            ['Email' => 'anonymous'],
            [],
            new ResolveInfo([])
        );

        /** @var Member $member */
        $member = $response['Member'];
        $this->assertTrue($member instanceof Member);
        $this->assertTrue($member->exists());
        $this->assertEquals($member->Email, 'anonymous');
        $this->assertNotNull($response['Token']);
    }

    /**
     * @throws ValidationException
     */
    public function testResolveInvalidWithoutAllowedAnonymous()
    {
        $authenticator = CreateTokenMutationCreator::singleton();
        $response = $authenticator->resolve(
            null,
            ['Email' => 'anonymous'],
            [],
            new ResolveInfo([])
        );

        $this->assertNull($response['Member']);
        $this->assertNull($response['Token']);
    }
}
