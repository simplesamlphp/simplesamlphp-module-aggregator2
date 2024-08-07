<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\aggregator\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module\aggregator2\Controller;
use SimpleSAML\Session;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Set of tests for the controllers in the "aggregator2" module.
 */
#[CoversClass(Controller\Aggregator::class)]
class AggregatorTest extends TestCase
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Configuration */
    protected Configuration $moduleConfig;

    /** @var \SimpleSAML\Session */
    protected Session $session;


    /**
     * Set up for each test.
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->config = Configuration::loadFromArray(
            [
                'module.enable' => ['aggregator2' => true],
            ],
            '[ARRAY]',
            'simplesaml',
        );

        $this->session = Session::getSessionFromRequest();

        Configuration::setPreLoadedConfig($this->config, 'config.php');

        Configuration::setPreLoadedConfig(
            Configuration::loadFromArray(
                [
                    'example' => [
                        'sources' => [
                            [
                                'url' => 'tests/metadata/example.xml',
                            ],
                        ],
                    ],

                    'test' => [
                    ],

                    'bogus' => [
                    ],
                ],
                '[ARRAY]',
                'simplesaml',
            ),
            'module_aggregator2.php',
        );
    }


    /**
     * Test that accessing the index-page results in a Template being returned.
     */
    public function testMain(): void
    {
        $c = new Controller\Aggregator($this->config, $this->session);
        $response = $c->main();

        $this->assertTrue($response->isSuccessful());
        $this->assertInstanceOf(Template::class, $response);
    }


    /**
     * Test that accessing the get-page without id results in a BadRequest exception.
     */
    public function testGetWithoutId(): void
    {
        $request = Request::create(
            '/get',
            'GET',
        );

        $c = new Controller\Aggregator($this->config, $this->session);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage("BADREQUEST('%REASON%' => 'Missing required parameter \"id\".')");

        $c->get($request);
    }


    /**
     * Test that accessing the get-page with id, set and exclude results in a response.
     */
    public function testGetWithId(): void
    {
        $request = Request::create(
            '/get',
            'GET',
            [
                'id' => 'example',
                'set' => 'saml2',
                'exclude' => 'saml2-aa',
            ],
        );

        $c = new Controller\Aggregator($this->config, $this->session);
        $response = $c->get($request);

        $this->assertTrue($response->isSuccessful());
        $this->assertEquals('application/samlmetadata+xml', $response->headers->get('Content-Type'));
        $this->assertEquals('filename=example.xml', $response->headers->get('Content-Disposition'));
        $this->assertInstanceOf(Response::class, $response);
    }


    /**
     * Test that accessing the get-page with allowed MimeType results in the MimeType actually set.
     */
    public function testGetWithAllowedMime(): void
    {
        $request = Request::create(
            '/get',
            'GET',
            [
                'id' => 'example',
                'set' => 'saml2',
                'exclude' => 'saml2-aa',
                'mimetype' => 'text/plain',
            ],
        );

        $c = new Controller\Aggregator($this->config, $this->session);
        $response = $c->get($request);

        $this->assertTrue($response->isSuccessful());
        $this->assertEquals('text/plain', $response->headers->get('Content-Type'));
        $this->assertEquals('filename=example.xml', $response->headers->get('Content-Disposition'));
        $this->assertInstanceOf(Response::class, $response);
    }


    /**
     * Test that accessing the get-page with non-allowed MimeType results in the default being set.
     */
    public function testGetWithNonAllowedMime(): void
    {
        $request = Request::create(
            '/get',
            'GET',
            [
                'id' => 'example',
                'set' => 'saml2',
                'exclude' => 'saml2-aa',
                'mimetype' => 'something/stupid',
            ],
        );

        $c = new Controller\Aggregator($this->config, $this->session);
        $response = $c->get($request);

        $this->assertTrue($response->isSuccessful());
        $this->assertEquals('application/samlmetadata+xml', $response->headers->get('Content-Type'));
        $this->assertEquals('filename=example.xml', $response->headers->get('Content-Disposition'));
        $this->assertInstanceOf(Response::class, $response);
    }
}
