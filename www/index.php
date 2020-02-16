<?php

use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module;
use SimpleSAML\XHTML\Template;

$ssp_cf = Configuration::getInstance();
$mod_cf = Configuration::getConfig('module_aggregator2.php');

// get list of sources
$names = array_keys($mod_cf->toArray());
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

$t = new Template($ssp_cf, 'aggregator2:list.twig');
$t->data['sources'] = $sources;
$t->send();
