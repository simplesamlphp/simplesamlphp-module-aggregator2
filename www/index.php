<?php

$ssp_cf = \SimpleSAML\Configuration::getInstance();
$mod_cf = \SimpleSAML\Configuration::getConfig('module_aggregator2.php');

// get list of sources
$names = array_keys($mod_cf->toArray());
$sources = [];

foreach ($names as $name) {
    $encId = urlencode($name);

    $sources[$name] = [
        'name' => SimpleSAML\Module::getModuleURL(
            'aggregator2/get.php',
            ['id' => $encId]
        ),
        'text' => SimpleSAML\Module::getModuleURL(
            'aggregator2/get.php',
            ['id' => $encId, 'mimetype' => 'text/plain']
        ),
        'xml' => SimpleSAML\Module::getModuleURL(
            'aggregator2/get.php',
            ['id' => $encId, 'mimetype' => 'application/xml']
        ),
    ];
}

$t = new \SimpleSAML\XHTML\Template($ssp_cf, 'aggregator2:list.php');
$t->data['sources'] = $sources;
$t->show();
