<?php

namespace SimpleSAML\Module\aggregator2;

use Exception;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\Constants;
use SAML2\SignedElement;
use SAML2\Utils as SAML2_Utils;
use SAML2\XML\md\EntitiesDescriptor;
use SAML2\XML\md\EntityDescriptor;
use SAML2\XML\mdrpi\RegistrationInfo;
use SAML2\XML\mdrpi\PublicationInfo;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Utils;

/**
 * Class which implements a basic metadata aggregator.
 *
 * @package SimpleSAMLphp
 */
class Aggregator
{
    /**
     * The list of signature algorithms supported by the aggregator.
     *
     * @var array
     */
    public static array $SUPPORTED_SIGNATURE_ALGORITHMS = [
        XMLSecurityKey::RSA_SHA1,
        XMLSecurityKey::RSA_SHA256,
        XMLSecurityKey::RSA_SHA384,
        XMLSecurityKey::RSA_SHA512,
    ];

    /**
     * The ID of this aggregator.
     *
     * @var string
     */
    protected string $id;

    /**
     * Our log "location".
     *
     * @var string
     */
    protected string $logLoc;

    /**
     * Which cron-tag this should be updated in.
     *
     * @var string|null
     */
    protected ?string $cronTag;

    /**
     * Absolute path to a cache directory.
     *
     * @var string|null
     */
    protected ?string $cacheDirectory;

    /**
     * The entity sources.
     *
     * Array of sspmod_aggregator2_EntitySource objects.
     *
     * @var array
     */
    protected array $sources = [];

    /**
     * How long the generated metadata should be valid, as a number of seconds.
     *
     * This is used to set the validUntil attribute on the generated EntityDescriptor.
     *
     * @var int
     */
    protected int $validLength;

    /**
     * Duration we should cache generated metadata.
     *
     * @var int|null
     */
    protected ?int $cacheGenerated;

    /**
     * An array of entity IDs to exclude from the aggregate.
     *
     * @var string[]
     */
    protected array $excluded = [];

    /**
     * An indexed array of protocols to filter the aggregate by. keys can be any of:
     *
     * - urn:oasis:names:tc:SAML:1.1:protocol
     * - urn:oasis:names:tc:SAML:2.0:protocol
     *
     * Values will be true if enabled, false otherwise.
     *
     * @var array
     */
    protected $protocols = [];

    /**
     * An array of roles to filter the aggregate by. Keys can be any of:
     *
     * - \SAML2\XML\md\IDPSSODescriptor
     * - \SAML2\XML\md\SPSSODescriptor
     * - \SAML2\XML\md\AttributeAuthorityDescriptor
     *
     * Values will be true if enabled, false otherwise.
     *
     * @var array
     */
    protected array $roles;

    /**
     * The key we should use to sign the metadata.
     *
     * @var string|null
     */
    protected ?string $signKey;

    /**
     * The password for the private key.
     *
     * @var string|null
     */
    protected ?string $signKeyPass;

    /**
     * The certificate of the key we sign the metadata with.
     *
     * @var string|null
     */
    protected ?string $signCert;

    /**
     * The algorithm to use for metadata signing.
     *
     * @var string|null
     */
    protected ?string $signAlg;

    /**
     * The CA certificate file that should be used to validate https-connections.
     *
     * @var string|null
     */
    protected ?string $sslCAFile;

    /**
     * The cache ID for our generated metadata.
     *
     * @var string
     */
    protected string $cacheId = 'dummy';

    /**
     * The cache tag for our generated metadata.
     *
     * This tag is used to make sure that a config change
     * invalidates our cached metadata.
     *
     * @var string
     */
    protected string $cacheTag = 'dummy';

    /**
     * The registration information for our generated metadata.
     *
     * @var array
     */
    protected array $regInfo;

    /**
     * The publication information for our generated metadata.
     *
     * @var array
     */
    protected array $pubInfo;


    /**
     * Initialize this aggregator.
     *
     * @param string $id  The id of this aggregator.
     * @param \SimpleSAML\Configuration $config  The configuration for this aggregator.
     */
    protected function __construct(string $id, Configuration $config)
    {
        $sysUtils = new Utils\System();
        $this->id = $id;
        $this->logLoc = 'aggregator2:' . $this->id . ': ';

        $this->cronTag = $config->getString('cron.tag', null);

        $this->cacheDirectory = $config->getString('cache.directory', null);
        if ($this->cacheDirectory !== null) {
            $this->cacheDirectory = $sysUtils->resolvePath($this->cacheDirectory);
        }

        $this->cacheGenerated = $config->getInteger('cache.generated', null);
        if ($this->cacheGenerated !== null) {
            $this->cacheId = sha1($this->id);
            $this->cacheTag = sha1(serialize($config));
        }

        // configure entity IDs excluded by default
        $this->excludeEntities($config->getArrayize('exclude', []));

        // configure filters
        $this->setFilters($config->getArrayize('filter', []));

        $this->validLength = $config->getInteger('valid.length', 7 * 24 * 60 * 60);

        $globalConfig = Configuration::getInstance();
        $certDir = $globalConfig->getPathValue('certdir', 'cert/');

        $signKey = $config->getString('sign.privatekey', null);
        if ($signKey !== null) {
            $signKey = $sysUtils->resolvePath($signKey, $certDir);
            $sk = @file_get_contents($signKey);
            if ($sk === false) {
                throw new Exception('Unable to load private key from ' . var_export($signKey, true));
            }
            $this->signKey = $sk;
        }

        $this->signKeyPass = $config->getString('sign.privatekey_pass', null);

        $signCert = $config->getString('sign.certificate', null);
        if ($signCert !== null) {
            $signCert = $sysUtils->resolvePath($signCert, $certDir);
            $sc = @file_get_contents($signCert);
            if ($sc === false) {
                throw new Exception('Unable to load certificate file from ' . var_export($signCert, true));
            }
            $this->signCert = $sc;
        }

        $this->signAlg = $config->getString('sign.algorithm', XMLSecurityKey::RSA_SHA256);
        if (!in_array($this->signAlg, self::$SUPPORTED_SIGNATURE_ALGORITHMS)) {
            throw new Exception('Unsupported signature algorithm ' . var_export($this->signAlg, true));
        }

        $this->sslCAFile = $config->getString('ssl.cafile', null);

        $this->regInfo = $config->getArray('RegistrationInfo', []);
        $this->pubInfo = $config->getArray('PublicationInfo', []);

        $this->initSources($config->getArray('sources', []));
    }


    /**
     * Populate the sources array.
     *
     * This is called from the constructor, and can be overridden in subclasses.
     *
     * @param array $sources  The sources as an array of \SimpleSAML\Configuration objects.
     */
    protected function initSources(array $sources): void
    {
        foreach ($sources as $source) {
            $this->sources[] = new EntitySource($this, Configuration::loadFromArray($source));
        }
    }


    /**
     * Return an instance of the aggregator with the given id.
     *
     * @param string $id  The id of the aggregator.
     * @return Aggregator
     */
    public static function getAggregator(string $id): Aggregator
    {
        $config = Configuration::getConfig('module_aggregator2.php');
        /** @psalm-suppress PossiblyNullArgument */
        return new Aggregator($id, $config->getConfigItem($id, []));
    }


    /**
     * Retrieve the ID of the aggregator.
     *
     * @return string  The ID of this aggregator.
     */
    public function getId(): string
    {
        return $this->id;
    }


    /**
     * Add an item to the cache.
     *
     * @param string $id  The identifier of this data.
     * @param string $data  The data.
     * @param int $expires  The timestamp the data expires.
     * @param string|null $tag  An extra tag that can be used to verify the validity of the cached data.
     */
    public function addCacheItem(string $id, string $data, int $expires, string $tag = null): void
    {
        $sysUtils = new Utils\System();
        $cacheFile = strval($this->cacheDirectory) . '/' . $id;
        try {
            $sysUtils->writeFile($cacheFile, $data);
        } catch (Exception $e) {
            Logger::warning($this->logLoc . 'Unable to write to cache file ' . var_export($cacheFile, true));
            return;
        }

        $expireInfo = (string)$expires;
        if ($tag !== null) {
            $expireInfo .= ':' . $tag;
        }

        $expireFile = $cacheFile . '.expire';
        try {
            $sysUtils->writeFile($expireFile, $expireInfo);
        } catch (Exception $e) {
            Logger::warning($this->logLoc . 'Unable to write expiration info to ' . var_export($expireFile, true));
        }
    }


    /**
     * Check validity of cached data.
     *
     * @param string $id  The identifier of this data.
     * @param string|null $tag  The tag that was passed to addCacheItem.
     * @return bool  TRUE if the data is valid, FALSE if not.
     */
    public function isCacheValid(string $id, string $tag = null): bool
    {
        $cacheFile = strval($this->cacheDirectory) . '/' . $id;
        if (!file_exists($cacheFile)) {
            return false;
        }

        $expireFile = $cacheFile . '.expire';
        if (!file_exists($expireFile)) {
            return false;
        }

        $expireData = @file_get_contents($expireFile);
        if ($expireData === false) {
            return false;
        }

        $expireData = explode(':', $expireData, 2);

        $expireTime = intval($expireData[0]);
        if ($expireTime <= time()) {
            return false;
        }

        if (count($expireData) === 1) {
            $expireTag = null;
        } else {
            $expireTag = $expireData[1];
        }
        if ($expireTag !== $tag) {
            return false;
        }

        return true;
    }


    /**
     * Get the cache item.
     *
     * @param string $id  The identifier of this data.
     * @param string|null $tag  The tag that was passed to addCacheItem.
     * @return string|null  The cache item, or NULL if it isn't cached or if it is expired.
     */
    public function getCacheItem(string $id, string $tag = null): ?string
    {
        if (!$this->isCacheValid($id, $tag)) {
            return null;
        }

        $cacheFile = strval($this->cacheDirectory) . '/' . $id;
        return @file_get_contents($cacheFile);
    }


    /**
     * Get the cache filename for the specific id.
     *
     * @param string $id  The identifier of the cached data.
     * @return string|null  The filename, or NULL if the cache file doesn't exist.
     */
    public function getCacheFile(string $id): ?string
    {
        $cacheFile = strval($this->cacheDirectory) . '/' . $id;
        if (!file_exists($cacheFile)) {
            return null;
        }

        return $cacheFile;
    }


    /**
     * Retrieve the SSL CA file path, if it is set.
     *
     * @return string|null  The SSL CA file path.
     */
    public function getCAFile(): ?string
    {
        return $this->sslCAFile;
    }


    /**
     * Sign the generated EntitiesDescriptor.
     */
    protected function addSignature(SignedElement $element): void
    {
        if ($this->signKey === null) {
            return;
        }

        /** @var string $this->signAlg */
        $privateKey = new XMLSecurityKey($this->signAlg, ['type' => 'private']);
        if ($this->signKeyPass !== null) {
            $privateKey->passphrase = $this->signKeyPass;
        }
        $privateKey->loadKey($this->signKey, false);

        $element->setSignatureKey($privateKey);

        if ($this->signCert !== null) {
            $element->setCertificates([$this->signCert]);
        }
    }


    /**
     * Recursively browse the children of an EntitiesDescriptor element looking for EntityDescriptor elements, and
     * return an array containing all of them.
     *
     * @param \SAML2\XML\md\EntitiesDescriptor $entity The source EntitiesDescriptor that holds the entities to extract.
     *
     * @return array An array containing all the EntityDescriptors found.
     */
    private static function extractEntityDescriptors(EntitiesDescriptor $entity): array
    {
        $results = [];
        foreach ($entity->getChildren() as $child) {
            if ($child instanceof EntityDescriptor) {
                $results[] = $child;
                continue;
            }

            $results = array_merge($results, self::extractEntityDescriptors($child));
        }
        return $results;
    }


    /**
     * Retrieve all entities as an EntitiesDescriptor.
     *
     * @return \SAML2\XML\md\EntitiesDescriptor  The entities.
     */
    protected function getEntitiesDescriptor(): EntitiesDescriptor
    {
        $ret = new EntitiesDescriptor();
        $now = time();
        $extensions = [];

        // add RegistrationInfo extension if enabled
        if (!empty($this->regInfo)) {
            $ri = new RegistrationInfo();
            $ri->setRegistrationInstant($now);
            foreach ($this->regInfo as $riName => $riValues) {
                switch ($riName) {
                    case 'authority':
                        $ri->setRegistrationAuthority($riValues);
                        break;
                    case 'instant':
                        $ri->setRegistrationInstant(SAML2_Utils::xsDateTimeToTimestamp($riValues));
                        break;
                    case 'policies':
                        $ri->setRegistrationPolicy($riValues);
                        break;
                    default:
                        Logger::warning(
                            "Unable to apply unknown configuration setting \$config['RegistrationInfo']['"
                            . strval($riValues) . "'; skipping."
                        );
                        break;
                }
            }
            $extensions[] = $ri;
        }

        // add PublicationInfo extension if enabled
        if (!empty($this->pubInfo)) {
            $pi = new PublicationInfo();
            $pi->setCreationInstant($now);
            foreach ($this->pubInfo as $piName => $piValues) {
                switch ($piName) {
                    case 'publisher':
                        $pi->setPublisher($piValues);
                        break;
                    case 'publicationId':
                        $pi->setPublicationId($piValues);
                        break;
                    case 'instant':
                        $pi->setCreationInstant(SAML2_Utils::xsDateTimeToTimestamp($piValues));
                        break;
                    case 'policies':
                        $pi->setUsagePolicy($piValues);
                        break;
                    default:
                        Logger::warning(
                            "Unable to apply unknown configuration setting \$config['PublicationInfo']['"
                            . strval($piValues) . "'; skipping."
                        );
                        break;
                }
            }
            $extensions[] = $pi;
        }
        $ret->setExtensions($extensions);

        foreach ($this->sources as $source) {
            $m = $source->getMetadata();
            if ($m === null) {
                continue;
            }
            if ($m instanceof EntityDescriptor) {
                $ret->addChildren($m);
            } elseif ($m instanceof EntitiesDescriptor) {
                $ret->setChildren(array_merge($ret->getChildren(), self::extractEntityDescriptors($m)));
            }
        }

        $ret->setChildren(array_unique($ret->getChildren(), SORT_REGULAR));
        $ret->validUntil = $now + $this->validLength;

        return $ret;
    }


    /**
     * Recursively traverse the children of an EntitiesDescriptor, removing those entities listed in the $entities
     * property. Returns the EntitiesDescriptor with the entities filtered out.
     *
     * @param \SAML2\XML\md\EntitiesDescriptor $descriptor The EntitiesDescriptor from where to exclude entities.
     *
     * @return \SAML2\XML\md\EntitiesDescriptor The EntitiesDescriptor with excluded entities filtered out.
     */
    protected function exclude(EntitiesDescriptor $descriptor): EntitiesDescriptor
    {
        if (empty($this->excluded)) {
            return $descriptor;
        }

        $filtered = [];
        foreach ($descriptor->getChildren() as $child) {
            if ($child instanceof EntityDescriptor) {
                if (in_array($child->getEntityID(), $this->excluded)) {
                    continue;
                }
                $filtered[] = $child;
            }

            if ($child instanceof EntitiesDescriptor) {
                $filtered[] = $this->exclude($child);
            }
        }

        $descriptor->setChildren($filtered);
        return $descriptor;
    }


    /**
     * Recursively traverse the children of an EntitiesDescriptor, keeping only those entities with the roles listed in
     * the $roles property, and support for the protocols listed in the $protocols property. Returns the
     * EntitiesDescriptor containing only those entities.
     *
     * @param \SAML2\XML\md\EntitiesDescriptor $descriptor The EntitiesDescriptor to filter.
     *
     * @return \SAML2\XML\md\EntitiesDescriptor The EntitiesDescriptor with only the entities filtered.
     */
    protected function filter(EntitiesDescriptor $descriptor): EntitiesDescriptor
    {
        if (empty($this->roles) || empty($this->protocols)) {
            return $descriptor;
        }

        $enabled_roles = array_keys($this->roles, true);
        $enabled_protos = array_keys($this->protocols, true);

        $filtered = [];
        foreach ($descriptor->getChildren() as $child) {
            if ($child instanceof EntityDescriptor) {
                foreach ($child->getRoleDescriptor() as $role) {
                    if (in_array(get_class($role), $enabled_roles)) {
                        // we found a role descriptor that is enabled by our filters, check protocols
                        if (array_intersect($enabled_protos, $role->getProtocolSupportEnumeration()) !== []) {
                            // it supports some protocol we have enabled, add it
                            $filtered[] = $child;
                            break;
                        }
                    }
                }
            }

            if ($child instanceof EntitiesDescriptor) {
                $filtered[] = $this->filter($child);
            }
        }

        $descriptor->setChildren($filtered);
        return $descriptor;
    }


    /**
     * Set this aggregator to exclude a set of entities from the resulting aggregate.
     *
     * @param array $entities The entity IDs of the entities to exclude.
     */
    public function excludeEntities(array $entities): void
    {
        if (empty($entities)) {
            return;
        }
        $this->excluded = $entities;
        sort($this->excluded);
        $this->cacheId = sha1($this->cacheId . serialize($this->excluded));
    }


    /**
     * Set the internal filters according to one or more options:
     *
     * - 'saml2': all SAML2.0-capable entities.
     * - 'saml20-idp': all SAML2.0-capable identity providers.
     * - 'saml20-sp': all SAML2.0-capable service providers.
     * - 'saml20-aa': all SAML2.0-capable attribute authorities.
     *
     * @param array $set An array of the different roles and protocols to filter by.
     */
    public function setFilters(array $set): void
    {
        if (empty($set)) {
            return;
        }

        // configure filters
        $this->protocols = [
            Constants::NS_SAMLP                    => true,
        ];
        $this->roles = [
            'SAML2_XML_md_IDPSSODescriptor'             => true,
            'SAML2_XML_md_SPSSODescriptor'              => true,
            'SAML2_XML_md_AttributeAuthorityDescriptor' => true,
        ];

        // now translate from the options we have, to specific protocols and roles

        // check SAML 2.0 protocol
        $options = ['saml2', 'saml20-idp', 'saml20-sp', 'saml20-aa'];
        $this->protocols[Constants::NS_SAMLP] = (array_intersect($set, $options) !== []);

        // check IdP
        $options = ['saml2', 'saml20-idp'];
        $this->roles['SAML2_XML_md_IDPSSODescriptor'] = (array_intersect($set, $options) !== []);

        // check SP
        $options = ['saml2', 'saml20-sp'];
        $this->roles['SAML2_XML_md_SPSSODescriptor'] = (array_intersect($set, $options) !== []);

        // check AA
        $options = ['saml2', 'saml20-aa'];
        $this->roles['SAML2_XML_md_AttributeAuthorityDescriptor'] = (array_intersect($set, $options) !== []);

        $this->cacheId = sha1($this->cacheId . serialize($this->protocols) . serialize($this->roles));
    }


    /**
     * Retrieve the complete, signed metadata as text.
     *
     * This function will write the new metadata to the cache file, but will not return
     * the cached metadata.
     *
     * @return string  The metadata, as text.
     */
    public function updateCachedMetadata(): string
    {
        $ed = $this->getEntitiesDescriptor();
        $ed = $this->exclude($ed);
        $ed = $this->filter($ed);
        $this->addSignature($ed);

        $xml = $ed->toXML();
        $xml = $xml->ownerDocument->saveXML($xml);

        if ($this->cacheGenerated !== null) {
            Logger::debug($this->logLoc . 'Saving generated metadata to cache.');
            $this->addCacheItem($this->cacheId, $xml, time() + $this->cacheGenerated, $this->cacheTag);
        }

        return $xml;
    }


    /**
     * Retrieve the complete, signed metadata as text.
     *
     * @return string  The metadata, as text.
     */
    public function getMetadata(): string
    {
        if ($this->cacheGenerated !== null) {
            $xml = $this->getCacheItem($this->cacheId, $this->cacheTag);
            if ($xml !== null) {
                Logger::debug($this->logLoc . 'Loaded generated metadata from cache.');
                return $xml;
            }
        }

        return $this->updateCachedMetadata();
    }


    /**
     * Update the cached copy of our metadata.
     */
    public function updateCache(): void
    {
        foreach ($this->sources as $source) {
            $source->updateCache();
        }

        $this->updateCachedMetadata();
    }
}
