#!/usr/bin/env php
<?php

declare(strict_types=1);

require_once(dirname(__FILE__, 4) . '/lib/_autoload.php');

if ($argc < 2) {
    fwrite(STDERR, "Missing aggregator id.\n");
    exit(1);
}
$id = $argv[1];

error_reporting(E_ALL ^ E_NOTICE);
try {
    $aggregator = \SimpleSAML\Module\aggregator2\Aggregator::getAggregator($id);
    $xml = $aggregator->getMetadata();
    $xmlUtils = new \SimpleSAML\Utils\XML();
    $xml = $xmlUtils->formatXMLString($xml);
    echo $xml;
} catch (\Exception $e) {
    fwrite(STDERR, $e->getMessage() . "\n");
}
