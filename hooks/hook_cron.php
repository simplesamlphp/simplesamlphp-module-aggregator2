<?php

use Exception;
use SimpleSAML\Configuration;
use SimpleSAML\Module\aggregator2\Aggregator;

/**
 * cron hook to update aggregator2 metadata.
 *
 * @param array &$croninfo  Output
 */
function aggregator2_hook_cron(array &$croninfo): void
{
    assert('array_key_exists("summary", $croninfo)');
    assert('array_key_exists("tag", $croninfo)');

    $cronTag = $croninfo['tag'];

    $config = Configuration::getConfig('module_aggregator2.php');
    $config = $config->toArray();

    foreach ($config as $id => $c) {
        if (!isset($c['cron.tag'])) {
            continue;
        }
        if ($c['cron.tag'] !== $cronTag) {
            continue;
        }

        try {
            $a = Aggregator::getAggregator($id);
            $a->updateCache();
        } catch (Exception $e) {
            $croninfo['summary'][] = 'Error during aggregator2 cacheupdate: ' . $e->getMessage();
        }
    }
}
