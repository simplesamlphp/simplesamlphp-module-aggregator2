<?php

/**
 * Hook to add the aggregator2 lik to the frontpage.
 *
 * @param array &$links The links on the frontpage, split into sections.
 * @return void
 */
function aggregator2_hook_frontpage(&$links)
{
    assert('is_array($links)');
    assert('array_key_exists("links", $links)');

    $links['federation'][] = [
        'href' => \SimpleSAML\Module::getModuleURL('aggregator2/'),
        'text' => '{aggregator2:aggregator:frontpage_link}',
    ];
}
