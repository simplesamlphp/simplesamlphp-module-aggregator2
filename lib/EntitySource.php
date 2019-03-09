<?php

namespace SimpleSAML\Module\aggregator2;

use \SimpleSAML\Configuration;
use \SimpleSAML\Error\Exception;
use \SimpleSAML\Logger;
use \SimpleSAML\Utils\Config;
use \SimpleSAML\Utils\HTTP;

use \SAML2\Utils;
use \SAML2\XML\md\EntitiesDescriptor;
use \SAML2\XML\md\EntityDescriptor;

use \RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * Class for loading metadata from files and URLs.
 *
 * @package SimpleSAMLphp
 */
class EntitySource
{
    /**
     * Our log "location".
     *
     * @var string
     */
    protected $logLoc;

    /**
     * The aggregator we belong to.
     *
     * @var \SimpleSAML\Module\aggregator2\Aggregator
     */
    protected $aggregator;

    /**
     * The URL we should fetch it from.
     *
     * @var string
     */
    protected $url;

    /**
     * The SSL CA file that should be used to validate the connection.
     *
     * @var string|null
     */
    protected $sslCAFile;

    /**
     * The certificate we should use to validate downloaded metadata.
     *
     * @var string|null
     */
    protected $certificate;

    /**
     * The parsed metadata.
     *
     * @var \SAML2\XML\md\EntitiesDescriptor|\SAML2\XML\md\EntityDescriptor|null
     */
    protected $metadata = null;

    /**
     * The cache ID.
     *
     * @var string
     */
    protected $cacheId;

    /**
     * The cache tag.
     *
     * @var string
     */
    protected $cacheTag;

    /**
     * Whether we have attempted to update the cache already.
     *
     * @var bool
     */
    protected $updateAttempted = false;


    /**
     * Initialize this EntitySource.
     *
     * @param \SimpleSAML\Configuration $config  The configuration.
     */
    public function __construct(Aggregator $aggregator, Configuration $config)
    {
        $this->logLoc = 'aggregator2:'.$aggregator->getId().': ';
        $this->aggregator = $aggregator;

        $this->url = $config->getString('url');
        $this->sslCAFile = $config->getString('ssl.cafile', null);
        if ($this->sslCAFile === null) {
            $this->sslCAFile = $aggregator->getCAFile();
        }

        $this->certificate = $config->getString('cert', null);

        $this->cacheId = sha1($this->url);
        $this->cacheTag = sha1(serialize($config));
    }


    /**
     * Retrieve and parse the metadata.
     *
     * @return \SAML2\XML\md\EntitiesDescriptor|\SAML2\XML\md\EntityDescriptor|null
     * The downloaded metadata or NULL if we were unable to download or parse it.
     */
    private function downloadMetadata()
    {
        Logger::debug($this->logLoc.'Downloading metadata from '.var_export($this->url, true));

        $context = ['ssl' => []];
        if ($this->sslCAFile !== null) {
            $context['ssl']['cafile'] = Config::getCertPath($this->sslCAFile);
            Logger::debug($this->logLoc.'Validating https connection against CA certificate(s) found in '.
                var_export($context['ssl']['cafile'], true));
            $context['ssl']['verify_peer'] = true;
            $context['ssl']['CN_match'] = parse_url($this->url, PHP_URL_HOST);
        }

        try {
            $data = HTTP::fetch($this->url, $context, false);
        } catch (\SimpleSAML\Error\Exception $e) {
            Logger::error($this->logLoc.'Unable to load metadata from '.var_export($this->url, true));
            return null;
        }

        $doc = new \DOMDocument();
        /** @var string $data */
        $res = $doc->loadXML($data);
        if (!$res) {
            Logger::error($this->logLoc.'Error parsing XML from '.var_export($this->url, true));
            return null;
        }

        $root = Utils::xpQuery($doc->firstChild, '/saml_metadata:EntityDescriptor|/saml_metadata:EntitiesDescriptor');
        if (count($root) === 0) {
            Logger::error($this->logLoc.'No <EntityDescriptor> or <EntitiesDescriptor> in metadata from '.
                var_export($this->url, true));
            return null;
        }

        if (count($root) > 1) {
            Logger::error($this->logLoc.'More than one <EntityDescriptor> or <EntitiesDescriptor> in metadata from '.
                var_export($this->url, true));
            return null;
        }

        $root = $root[0];
        try {
            if ($root->localName === 'EntityDescriptor') {
                $md = new EntityDescriptor($root);
            } else {
                $md = new EntitiesDescriptor($root);
            }
        } catch (\Exception $e) {
            Logger::error($this->logLoc.'Unable to parse metadata from '.
                var_export($this->url, true).': '.$e->getMessage());
            return null;
        }

        if ($this->certificate !== null) {
            $file = Config::getCertPath($this->certificate);
            $certData = file_get_contents($file);
            if ($certData === false) {
                throw new Exception('Error loading certificate from '.var_export($file, true));
            }

            // Extract the public key from the certificate for validation
            $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, ['type'=>'public']);
            $key->loadKey($file, true);

            if (!$md->validate($key)) {
                Logger::error($this->logLoc.'Error validating signature on metadata.');
                return null;
            }
            Logger::debug($this->logLoc.'Validated signature on metadata from '.var_export($this->url, true));
        }

        return $md;
    }


    /**
     * Attempt to update our cache file.
     * @return void
     */
    public function updateCache()
    {
        if ($this->updateAttempted) {
            return;
        }
        $this->updateAttempted = true;

        $this->metadata = $this->downloadMetadata();
        if ($this->metadata === null) {
            return;
        }

        $expires = time() + 24*60*60; // Default expires in one day

        if ($this->metadata->validUntil !== null && $this->metadata->validUntil < $expires) {
            $expires = $this->metadata->validUntil;
        }

        $metadataSerialized = serialize($this->metadata);

        $this->aggregator->addCacheItem($this->cacheId, $metadataSerialized, $expires, $this->cacheTag);
    }


    /**
     * Retrieve the metadata file.
     *
     * This function will check its cached copy, to see whether it can be used.
     *
     * @return \SAML2\XML\md\EntityDescriptor|\SAML2\XML\md\EntitiesDescriptor|null  The downloaded metadata.
     */
    public function getMetadata()
    {
        if ($this->metadata !== null) {
            /* We have already downloaded the metdata. */
            return $this->metadata;
        }

        if (!$this->aggregator->isCacheValid($this->cacheId, $this->cacheTag)) {
            $this->updateCache();
            /** @psalm-suppress TypeDoesNotContainType */
            if ($this->metadata !== null) {
                return $this->metadata;
            }
            /* We were unable to update the cache - use cached metadata. */
        }

        $cacheFile = $this->aggregator->getCacheFile($this->cacheId);

        if (is_null($cacheFile) || !file_exists($cacheFile)) {
            Logger::error($this->logLoc . 'No cached metadata available.');
            return null;
        }

        Logger::debug($this->logLoc.'Using cached metadata from '.var_export($cacheFile, true));

        $metadata = file_get_contents($cacheFile);
        if ($metadata !== false) {
            $this->metadata = unserialize($metadata);
            return $this->metadata;
        }

        return null;
    }
}
