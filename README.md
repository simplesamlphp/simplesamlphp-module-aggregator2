Aggregator 2
============

This is a SimpleSAMLphp module for metadata aggregation. It is designed to preserve most of the common
metadata items, and it also attempts to preserve unknown elements. Metadata sources are parsed and rebuilt,
so small differences between the original sources and the metadata generated may occur. More specifically:

* Signatures will be removed from every signed metadata source.
* All sources will be wrapped up in an EntitiesDescriptor element.

Note: This aggregator works only with XML metadata, and does its work independently of other parts of
SimpleSAMLphp, such as the metarefresh module.

Installation
------------

Once you have installed SimpleSAMLphp, installing this module is very simple. Just execute the following
command in the root of your SimpleSAMLphp installation:

```
composer.phar require simplesamlphp/simplesamlphp-module-aggregator2:dev-master
```

where `dev-master` instructs Composer to install the `master` branch from the Git repository. See the
[releases](https://github.com/simplesamlphp/simplesamlphp-module-aggregator2/releases) available if you
want to use a stable version of the module.

