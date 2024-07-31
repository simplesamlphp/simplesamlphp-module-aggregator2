<?php

declare(strict_types=1);

namespace SimpleSAML\Module\aggregator2;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use Exception;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\SAML2\Constants as C;
use SimpleSAML\SAML2\XML\md\EntitiesDescriptor;
use SimpleSAML\SAML2\XML\md\EntityDescriptor;
use SimpleSAML\SAML2\XML\md\Extensions;
use SimpleSAML\SAML2\XML\mdrpi\PublicationInfo;
use SimpleSAML\SAML2\XML\mdrpi\RegistrationInfo;
use SimpleSAML\Utils;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\CryptoEncoding\PEM;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\XML\ds\KeyInfo;
use SimpleSAML\XMLSecurity\XML\ds\X509Certificate;
use SimpleSAML\XMLSecurity\XML\ds\X509Data;
use SimpleSAML\XMLSecurity\XML\SignableElementInterface;

use function array_intersect;
use function array_keys;
use function array_merge;
use function array_unique;
use function explode;
use function file_exists;
use function file_get_contents;
use function get_class;
use function in_array;
use function intval;
use function serialize;
use function sha1;
use function strval;
use function time;
use function var_export;

/**
 * Class which implements a basic metadata aggregator.
 *
 * @package SimpleSAMLphp
 */
class Aggregator
{
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
     * Array of \SimpleSAML\Module\aggregator2\EntitySource objects.
     *
     * @var array<\SimpleSAML\Module\aggregator2\EntitySource>
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
     * @var \DateInterval|null
     */
    protected ?DateInterval $cacheGenerated = null;

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
     * @var string[]
     */
    protected array $protocols = [];

    /**
     * An array of roles to filter the aggregate by. Keys can be any of:
     *
     * - SimpleSAML\SAML2\XML\md\IDPSSODescriptor
     * - SimpleSAML\SAML2\XML\md\SPSSODescriptor
     * - SimpleSAML\SAML2\XML\md\AttributeAuthorityDescriptor
     *
     * Values will be true if enabled, false otherwise.
     *
     * @var array<\SimpleSAML\SAML2\XML\md\AbstractSSODescriptor>
     */
    protected array $roles;

    /**
     * The key we should use to sign the metadata.
     *
     * @var \SimpleSAML\XMLSecurity\CryptoEncoding\PEM|null
     */
    protected ?PEM $signKey = null;

    /**
     * The password for the private key.
     *
     * @var string|null
     */
    protected ?string $signKeyPass;

    /**
     * The certificate of the key we sign the metadata with.
     *
     * @var \SimpleSAML\XMLSecurity\CryptoEncoding\PEM|null
     */
    protected ?PEM $signCert;

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
     * @var string[]
     */
    protected array $regInfo;

    /**
     * The publication information for our generated metadata.
     *
     * @var string[]
     */
    protected array $pubInfo;

    /**
     * The name for the EntitiesDescriptor
     *
     * @var string|null
     */
    protected ?string $name;


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
        $this->name = $config->getOptionalString('name', null);
        $this->logLoc = 'aggregator2:' . $this->id . ': ';
        $this->cronTag = $config->getOptionalString('cron.tag', null);

        $this->cacheDirectory = $config->getOptionalString('cache.directory', $sysUtils->getTempDir());
        if ($this->cacheDirectory !== null) {
            $this->cacheDirectory = $sysUtils->resolvePath($this->cacheDirectory);
        }

        $cacheGenerated = $config->getOptionalString('cache.generated', null);
        Assert::nullOrValidDuration($cacheGenerated);
        if ($cacheGenerated !== null) {
            $this->cacheGenerated = new DateInterval($cacheGenerated);
            $this->cacheId = sha1($this->id);
            $this->cacheTag = sha1(serialize($config));
        }

        // configure entity IDs excluded by default
        $this->excludeEntities($config->getOptionalArrayize('exclude', []));

        // configure filters
        $this->setFilters($config->getOptionalArrayize('filter', []));

        $this->validLength = $config->getOptionalInteger('valid.length', 7 * 24 * 60 * 60);

        $globalConfig = Configuration::getInstance();
        $certDir = $globalConfig->getPathValue('certdir', 'cert/');

        $signKey = $config->getOptionalString('sign.privatekey', null);
        if ($signKey !== null) {
            $signKey = $sysUtils->resolvePath($signKey, $certDir);
            $this->signKey = PEM::fromFile($signKey);
        }

        $this->signKeyPass = $config->getOptionalString('sign.privatekey_pass', null);

        $signCert = $config->getOptionalString('sign.certificate', null);
        if ($signCert !== null) {
            $signCert = $sysUtils->resolvePath($signCert, $certDir);
            $this->signCert = PEM::fromFile($signCert);
        }

        $this->signAlg = $config->getOptionalString('sign.algorithm', C::SIG_RSA_SHA256);
        if (!in_array($this->signAlg, array_keys(C::$RSA_DIGESTS))) {
            throw new Exception('Unsupported signature algorithm ' . var_export($this->signAlg, true));
        }

        $this->sslCAFile = $config->getOptionalString('ssl.cafile', null);

        $this->regInfo = $config->getOptionalArray('RegistrationInfo', []);
        $this->pubInfo = $config->getOptionalArray('PublicationInfo', []);

        $this->initSources($config->getOptionalArray('sources', []));
    }


    /**
     * Populate the sources array.
     *
     * This is called from the constructor, and can be overridden in subclasses.
     *
     * @param array<mixed> $sources  The sources as an array of \SimpleSAML\Configuration objects.
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
        return new Aggregator($id, $config->getOptionalConfigItem($id, []));
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
     * @param \DateTimeImmutable $expires  The timestamp the data expires.
     * @param string|null $tag  An extra tag that can be used to verify the validity of the cached data.
     */
    public function addCacheItem(string $id, string $data, DateTimeImmutable $expires, string $tag = null): void
    {
        $sysUtils = new Utils\System();
        $cacheFile = strval($this->cacheDirectory) . '/' . $id;
        try {
            $sysUtils->writeFile($cacheFile, $data);
        } catch (Exception $e) {
            Logger::warning($this->logLoc . 'Unable to write to cache file ' . var_export($cacheFile, true));
            return;
        }

        $expireInfo = strval($expires->getTimestamp());
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
    protected function addSignature(SignableElementInterface $element): void
    {
        if ($this->signKey === null) {
            return;
        }

        $keyInfo = null;
        if ($this->signCert !== null) {
            $keyInfo = new KeyInfo(
                [
                    new X509Data(
                        [
                            new X509Certificate($this->signCert->getMaterial()),
                        ],
                    ),
                ],
            );
        }

        /** @var string $this->signAlg */
        $key = PrivateKey::fromFile($this->signKey, $this->signKeyPass);
        $signer = (new SignatureAlgorithmFactory())->getAlgorithm(
            $this->signAlg,
            $key,
        );

        $element->sign($signer, C::C14N_EXCLUSIVE_WITHOUT_COMMENTS, $keyInfo);
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
        $descriptors = array_merge($entity->getEntityDescriptors(), $entity->getEntitiesDescriptors());
        foreach ($descriptors as $child) {
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
     * @return \SimpleSAML\SAML2\XML\md\EntitiesDescriptor  The entities.
     */
    protected function getEntitiesDescriptor(): EntitiesDescriptor
    {
        $extensions = [];

        // add RegistrationInfo extension if enabled
        if (!empty($this->regInfo)) {
            $extensions[] = RegistrationInfo::fromArray($this->regInfo);
        }

        // add PublicationInfo extension if enabled
        if (!empty($this->pubInfo)) {
            $extensions[] = PublicationInfo::fromArray($this->pubInfo);
        }

        $children = [];
        foreach ($this->sources as $source) {
            $m = $source->getMetadata();
            if ($m === null) {
                continue;
            }

            if ($m instanceof EntityDescriptor) {
                $children[] = $m;
            } elseif ($m instanceof EntitiesDescriptor) {
                $children = array_merge($children, self::extractEntityDescriptors($m));
            }
        }
        $children = array_unique($children, SORT_REGULAR);

        $now = new DateTimeImmutable('@' . strval(time() + $this->validLength));
        $now = $now->setTimeZone(new DateTimeZone('Z'));

        $ret = new EntitiesDescriptor(
            entityDescriptors: $children,
            validUntil: $now,
            extensions: empty($extensions) ? null : new Extensions($extensions),
            Name: $this->name,
        );

        return $ret;
    }


    /**
     * Recursively traverse the children of an EntitiesDescriptor, removing those entities listed in the $entities
     * property. Returns the EntitiesDescriptor with the entities filtered out.
     *
     * @param \SimpleSAML\SAML2\XML\md\EntitiesDescriptor $descriptor
     *   The EntitiesDescriptor from where to exclude entities.
     *
     * @return \SimpleSAML\SAML2\XML\md\EntitiesDescriptor The EntitiesDescriptor with excluded entities filtered out.
     */
    protected function exclude(EntitiesDescriptor $descriptor): EntitiesDescriptor
    {
        if (empty($this->excluded)) {
            return $descriptor;
        }

        $descriptors = array_merge($descriptor->getEntityDescriptors(), $descriptor->getEntitiesDescriptors());
        $filtered = [];
        foreach ($descriptors as $child) {
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


        return new EntitiesDescriptor($filtered);
    }


    /**
     * Recursively traverse the children of an EntitiesDescriptor, keeping only those entities with the roles listed in
     * the $roles property, and support for the protocols listed in the $protocols property. Returns the
     * EntitiesDescriptor containing only those entities.
     *
     * @param \SimpleSAML\SAML2\XML\md\EntitiesDescriptor $descriptor The EntitiesDescriptor to filter.
     *
     * @return \SimpleSAML\SAML2\XML\md\EntitiesDescriptor The EntitiesDescriptor with only the entities filtered.
     */
    protected function filter(EntitiesDescriptor $descriptor): EntitiesDescriptor
    {
        if (empty($this->roles) || empty($this->protocols)) {
            return $descriptor;
        }

        $enabled_roles = array_keys($this->roles, true);
        $enabled_protos = array_keys($this->protocols, true);

        $descriptors = array_merge($descriptor->getEntityDescriptors(), $descriptor->getEntitiesDescriptors());
        $filtered = [];
        foreach ($descriptors as $child) {
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

        return new EntitiesDescriptor($filtered);
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
            C::NS_SAMLP => true,
        ];
        $this->roles = [
            'SimpleSAML\SAML2\XML\md\IDPSSODescriptor'             => true,
            'SimpleSAML\SAML2\XML\md\SPSSODescriptor'              => true,
            'SimpleSAML\SAML2\XML\md\AttributeAuthorityDescriptor' => true,
        ];

        // now translate from the options we have, to specific protocols and roles

        // check SAML 2.0 protocol
        $options = ['saml2', 'saml20-idp', 'saml20-sp', 'saml20-aa'];
        $this->protocols[C::NS_SAMLP] = (array_intersect($set, $options) !== []);

        // check IdP
        $options = ['saml2', 'saml20-idp'];
        $this->roles['SimpleSAML\SAML2\XML\md\IDPSSODescriptor'] = (array_intersect($set, $options) !== []);

        // check SP
        $options = ['saml2', 'saml20-sp'];
        $this->roles['SimpleSAML\SAML2\XML\md\SPSSODescriptor'] = (array_intersect($set, $options) !== []);

        // check AA
        $options = ['saml2', 'saml20-aa'];
        $this->roles['SimpleSAML\SAML2\XML\md\AttributeAuthorityDescriptor'] = (array_intersect($set, $options) !== []);

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
        $xml = $xml->ownerDocument?->saveXML($xml);

        if ($this->cacheGenerated !== null) {
            Logger::debug($this->logLoc . 'Saving generated metadata to cache.');
            $now = new DateTimeImmutable('now');
            $now = $now->setTimeZone(new DateTimezone('Z'));
            $this->addCacheItem($this->cacheId, $xml, $now->add($this->cacheGenerated), $this->cacheTag);
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
