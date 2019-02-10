<?php

$ssp_cf = \SimpleSAML\Configuration::getInstance();
$mod_cf = \SimpleSAML\Configuration::getConfig('module_aggregator2.php');

// get list of sources
$sources = $mod_cf->toArray();

$t = new \SimpleSAML\XHTML\Template($ssp_cf, 'aggregator2:list.php');
$t->data['sources'] = $sources;
$t->show();
