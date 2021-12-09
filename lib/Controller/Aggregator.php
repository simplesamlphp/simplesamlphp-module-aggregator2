<?php

declare(strict_types=1);

namespace SimpleSAML\Module\aggregator2\Controller;

use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module;
use SimpleSAML\Module\aggregator2\Aggregator as AttributeAggregator;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Controller class for the aggregator2 module.
 *
 * This class serves the different views available in the module.
 *
 * @package simplesamlphp/simplesamlphp-module-aggregator2
 */
class Aggregator
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Configuration */
    protected Configuration $moduleConfig;

    /** @var \SimpleSAML\Session */
    protected Session $session;

    /** @var string[] */
    private static array $allowedMimeTypes = [
        'text/plain',
        'application/samlmetadata-xml',
        'application/xml',
    ];

    /**
     * Controller constructor.
     *
     * It initializes the global configuration and session for the controllers implemented here.
     *
     * @param \SimpleSAML\Configuration $config The configuration to use by the controllers.
     * @param \SimpleSAML\Session $session The session to use by the controllers.
     *
     * @throws \Exception
     */
    public function __construct(
        Configuration $config,
        Session $session
    ) {
        $this->config = $config;
        $this->moduleConfig = Configuration::getConfig('module_aggregator2.php');
        $this->session = $session;
    }


    /**
     * @return \SimpleSAML\XHTML\Template
     */
    public function main(): Template
    {
        // get list of sources
        $names = array_keys($this->moduleConfig->toArray());

        $sources = [];
        foreach ($names as $name) {
            $encId = urlencode($name);

            $sources[$name] = [
                'name' => Module::getModuleURL(
                    'aggregator2/get.php',
                    ['id' => $encId]
                ),
                'text' => Module::getModuleURL(
                    'aggregator2/get.php',
                    ['id' => $encId, 'mimetype' => 'text/plain']
                ),
                'xml' => Module::getModuleURL(
                    'aggregator2/get.php',
                    ['id' => $encId, 'mimetype' => 'application/xml']
                ),
            ];
        }

        $t = new Template($this->config, 'aggregator2:list.twig');
        $t->data['sources'] = $sources;

        return $t;
    }


    /**
     * @param \Symfony\Component\HttpFoundation\Request $request The current request.
     *
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function get(Request $request): Response
    {
        $id = $request->get('id');
        if ($id === null) {
            throw new Error\BadRequest('Missing required parameter "id".');
        }
        $id = strval($id);

        $sets = [];
        $set = $request->get('set');
        if ($set !== null) {
            $sets = explode(',', $set);
        }

        $excluded_entities = [];
        $exclude = $request->get('exclude');
        if ($exclude !== null) {
            $excluded_entities = explode(',', $exclude);
        }

        $aggregator = AttributeAggregator::getAggregator($id);
        $aggregator->setFilters($sets);
        $aggregator->excludeEntities($excluded_entities);
        $xml = $aggregator->getMetadata();

        $mimeType = $request->get('mimetype');
        if (in_array($mimeType, self::$allowedMimeTypes)) {
            $mime = $mimeType;

            if ($mime === 'text/plain') {
                $xmlUtils = new Utils\XML();
                $xml = $xmlUtils->formatXMLString($xml);
            }
        } else {
            $mime = 'application/samlmetadata+xml';
        }

        $response = new Response();
        $response->headers->set('Content-Type', $mime);
        $response->headers->set('Content-Length', strval(strlen($xml)));
        $response->headers->set('Content-Disposition', 'filename=' . $id . '.xml');
        $response->setContent($xml);

        return $response;
    }
}
