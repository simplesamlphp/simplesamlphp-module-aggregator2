<?php

use SimpleSAML\Module;

/**
 * Hook to add the aggregator2 link to the frontpage.
 *
 * @param array &$links The links on the frontpage, split into sections.
 * @return void
 */
function aggregator2_hook_frontpage(array &$links): void
{
    assert('array_key_exists("links", $links)');

    $links['federation'][] = [
        'href' => Module::getModuleURL('aggregator2/'),
        'text' => '{aggregator2:aggregator:frontpage_link}',
    ];
}
