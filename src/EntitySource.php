<?php

declare(strict_types=1);

namespace SimpleSAML\Module\aggregator2;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use Exception;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\SAML2\Utils\XPath;
use SimpleSAML\SAML2\XML\md\EntitiesDescriptor;
use SimpleSAML\SAML2\XML\md\EntityDescriptor;
use SimpleSAML\Utils;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Key\PublicKey;

use function file_exists;
use function file_get_contents;
use function is_null;
use function parse_url;
use function serialize;
use function sha1;
use function strval;
use function time;
use function var_export;

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
    protected string $logLoc;

    /**
     * The aggregator we belong to.
     *
     * @var \SimpleSAML\Module\aggregator2\Aggregator
     */
    protected Aggregator $aggregator;

    /**
     * The URL we should fetch it from.
     *
     * @var string
     */
    protected string $url;

    /**
     * The SSL CA file that should be used to validate the connection.
     *
     * @var string|null
     */
    protected ?string $sslCAFile;

    /**
     * The certificate we should use to validate downloaded metadata.
     *
     * @var string|null
     */
    protected ?string $certificate;

    /**
     * The parsed metadata.
     *
     * @var \SimpleSAML\SAML2\XML\md\EntitiesDescriptor|\SimpleSAML\SAML2\XML\md\EntityDescriptor|null
     */
    protected EntityDescriptor|EntitiesDescriptor|null $metadata = null;

    /**
     * The cache ID.
     *
     * @var string
     */
    protected string $cacheId;

    /**
     * The cache tag.
     *
     * @var string
     */
    protected string $cacheTag;

    /**
     * Whether we have attempted to update the cache already.
     *
     * @var bool
     */
    protected bool $updateAttempted = false;


    /**
     * Initialize this EntitySource.
     *
     * @param \SimpleSAML\Configuration $config  The configuration.
     */
    public function __construct(Aggregator $aggregator, Configuration $config)
    {
        $this->logLoc = 'aggregator2:' . $aggregator->getId() . ': ';
        $this->aggregator = $aggregator;

        $this->url = $config->getString('url');
        $this->sslCAFile = $config->getOptionalString('ssl.cafile', null);
        if ($this->sslCAFile === null) {
            $this->sslCAFile = $aggregator->getCAFile();
        }

        $this->certificate = $config->getOptionalString('cert', null);

        $this->cacheId = sha1($this->url);
        $this->cacheTag = sha1(serialize($config));
    }


    /**
     * Retrieve and parse the metadata.
     *
     * @return \SimpleSAML\SAML2\XML\md\EntitiesDescriptor|\SimpleSAML\SAML2\XML\md\EntityDescriptor|null
     * The downloaded metadata or NULL if we were unable to download or parse it.
     */
    private function downloadMetadata(): EntitiesDescriptor|EntityDescriptor|null
    {
        Logger::debug($this->logLoc . 'Downloading metadata from ' . var_export($this->url, true));
        $configUtils = new Utils\Config();

        $context = ['ssl' => []];
        if ($this->sslCAFile !== null) {
            $context['ssl']['cafile'] = $configUtils->getCertPath($this->sslCAFile);
            Logger::debug(
                $this->logLoc . 'Validating https connection against CA certificate(s) found in ' .
                var_export($context['ssl']['cafile'], true),
            );
            $context['ssl']['verify_peer'] = true;
            $context['ssl']['CN_match'] = parse_url($this->url, PHP_URL_HOST);
        }

        try {
            $httpUtils = new Utils\HTTP();
            $data = $httpUtils->fetch($this->url, $context, false);
        } catch (Error\Exception $e) {
            Logger::error($this->logLoc . 'Unable to load metadata from ' . var_export($this->url, true));
            return null;
        }

        $doc = DOMDocumentFactory::create();
        /** @var string $data */
        $res = $doc->loadXML($data);
        if (!$res) {
            Logger::error($this->logLoc . 'Error parsing XML from ' . var_export($this->url, true));
            return null;
        }

        /** @psalm-var \DOMElement[] $root */
        $root = XPath::xpQuery(
            $doc->documentElement,
            '/saml_metadata:EntityDescriptor|/saml_metadata:EntitiesDescriptor',
            XPath::getXPath($doc->documentElement),
        );

        if (count($root) === 0) {
            Logger::error(
                $this->logLoc . 'No <EntityDescriptor> or <EntitiesDescriptor> in metadata from ' .
                var_export($this->url, true),
            );
            return null;
        }

        if (count($root) > 1) {
            Logger::error(
                $this->logLoc . 'More than one <EntityDescriptor> or <EntitiesDescriptor> in metadata from ' .
                var_export($this->url, true),
            );
            return null;
        }

        $root = $root[0];
        try {
            if ($root->localName === 'EntityDescriptor') {
                $md = EntityDescriptor::fromXML($root);
            } else {
                $md = EntitiesDescriptor::fromXML($root);
            }
        } catch (Exception $e) {
            Logger::error(
                $this->logLoc . 'Unable to parse metadata from ' .
                var_export($this->url, true) . ': ' . $e->getMessage(),
            );
            return null;
        }

        if ($this->certificate !== null) {
            $file = $configUtils->getCertPath($this->certificate);
            $verifier = (new SignatureAlgorithmFactory())->getAlgorithm(
                $md->getSignature()->getSignedInfo()->getSignatureMethod()->getAlgorithm(),
                PublicKey::fromFile($file),
            );

            /** @var \SimpleSAML\SAML2\XML\md\EntitiesDescriptor|\SimpleSAML\SAML2\XML\md\EntityDescriptor $md */
            $md = $md->verify($verifier);
            Logger::debug($this->logLoc . 'Validated signature on metadata from ' . var_export($this->url, true));
        }

        return $md;
    }


    /**
     * Attempt to update our cache file.
     */
    public function updateCache(): void
    {
        if ($this->updateAttempted) {
            return;
        }
        $this->updateAttempted = true;

        $this->metadata = $this->downloadMetadata();
        if ($this->metadata === null) {
            return;
        }

        $now = new DateTimeImmutable('@' . strval(time()));
        $now = $now->setTimeZone(new DateTimeZone('Z'));
        $expires = $now->add(new DateInterval('PT24H'));

        if ($this->metadata->getValidUntil() !== null && $this->metadata->getValidUntil() < $expires) {
            $expires = $this->metadata->getValidUntil();
        }

        $metadataSerialized = serialize($this->metadata);

        $this->aggregator->addCacheItem($this->cacheId, $metadataSerialized, $expires, $this->cacheTag);
    }


    /**
     * Retrieve the metadata file.
     *
     * This function will check its cached copy, to see whether it can be used.
     *
     * @return \SimpleSAML\SAML2\XML\md\EntityDescriptor|\SimpleSAML\SAML2\XML\md\EntitiesDescriptor|null
     *   The downloaded metadata.
     */
    public function getMetadata(): EntityDescriptor|EntitiesDescriptor|null
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

        Logger::debug($this->logLoc . 'Using cached metadata from ' . var_export($cacheFile, true));

        $metadata = file_get_contents($cacheFile);
        if ($metadata !== false) {
            $this->metadata = unserialize($metadata);
            return $this->metadata;
        }

        return null;
    }
}
