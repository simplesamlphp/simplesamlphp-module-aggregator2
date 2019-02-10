<?php

if (!isset($_REQUEST['id'])) {
    throw new \SimpleSAML\Error\BadRequest('Missing required parameter "id".');
}
$id = strval($_REQUEST['id']);

$set = null;
if (isset($_REQUEST['set'])) {
    $set = explode(',', $_REQUEST['set']);
}

$excluded_entities = null;
if (isset($_REQUEST['exclude'])) {
    $excluded_entities = explode(',', $_REQUEST['exclude']);
}

$aggregator = \SimpleSAML\Module\aggregator2\Aggregator::getAggregator($id);
$aggregator->setFilters($set);
$aggregator->excludeEntities($excluded_entities);
$xml = $aggregator->getMetadata();

$mimetype = 'application/samlmetadata+xml';
$allowedmimetypes = [
    'text/plain',
    'application/samlmetadata-xml',
    'application/xml',
];

if (isset($_GET['mimetype']) && in_array($_GET['mimetype'], $allowedmimetypes)) {
    $mimetype = $_GET['mimetype'];
}

if ($mimetype === 'text/plain') {
    $xml = \SimpleSAML\Utils\XML::formatXMLString($xml);
}

header('Content-Type: '.$mimetype);
header('Content-Length: ' . strlen($xml));

/*
 * At this point, if the ID was forged, getMetadata() would
 * have failed to find a valid metadata set, so we can trust it.
 */
header('Content-Disposition: filename='.$id.'.xml');

echo $xml;
