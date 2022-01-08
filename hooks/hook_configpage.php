<?php

declare(strict_types=1);

use SimpleSAML\Locale\Translate;
use SimpleSAML\Module;
use SimpleSAML\XHTML\Template;

/**
 * Hook to add the aggregator2 link to the frontpage.
 *
 * @param \SimpleSAML\XHTML\Template &$template The template that we should alter in this hook.
 */
function aggregator2_hook_configpage(Template &$template): void
{
    $template->data['links'][] = [
        'href' => Module::getModuleURL('aggregator2/'),
        'text' => Translate::noop('Aggregators'),
    ];

    $template->getLocalization()->addModuleDomain('aggregator2');
}
