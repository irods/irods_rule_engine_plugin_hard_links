# iRODS Rule Engine Plugin - Hard Links

Adds hard link support to iRODS.

## Requirements
- iRODS v4.2.8+
- irods-dev package
- irods-externals-boost package
- irods-externals-fmt package
- irods-externals-json package
- irods-externals-spdlog package
- irods-runtime package

## Compiling
```bash
$ git clone https://github.com/irods/irods_rule_engine_plugin_hard_links
$ git checkout 4-2-stable
$ mkdir _build
$ cd _build
$ cmake -GNinja ../irods_rule_engine_plugin_hard_links
$ ninja package
```
After compiling, you should now have a `deb` or `rpm` package with a name similar to the following:
```bash
irods-rule-engine-plugin-hard-links-<plugin_version>-<os>-<arch>.<deb|rpm>
```

## Installing
Ubuntu:
```bash
$ sudo dpkg -i irods-rule-engine-plugin-hard-links-*.deb
```
CentOS:
```bash
$ su -c yum localinstall irods-rule-engine-plugin-hard-links-*.rpm
```
If the installation was successful, you should now have a new shared library. The full path to the library
should be similar to the following:
```
<irods_lib_home>/plugins/rule_engines/libirods_rule_engine_plugin-hard_links.so
```

## Configuration
To enable, prepend the following plugin config to the list of rule engines in `/etc/irods/server_config.json`. 
The plugin config must be placed ahead of all plugins that do not support continuation.

Even though this plugin will process PEPs first due to it's positioning, subsequent Rule Engine Plugins (REP) will 
still be allowed to process the same PEPs without any issues.
```javascript
"rule_engines": [
    {
        "instance_name": "irods_rule_engine_plugin-hard_links-instance",
        "plugin_name": "irods_rule_engine_plugin-hard_links",
        "plugin_specific_configuration": {}
    },
    
    // ... Previously installed rule engine plugin configs ...
]
```

## How to Use
The following operations are supported:
- hard_links_create
- hard_link_create (alias of hard_links_create)

### Invoking operations via the Plugin
To invoke an operation through the plugin, JSON must be passed using the following structure:
```javascript
{
    // One of the operations listed above.
    // Because there is only one operation at this time, this should
    // be set to "hard_link_create".
    "operation": "<value>",

    // The absolute path of the source data object.
    "logical_path": "<value>",

    // The replica number identifying a specific replica under the
    // source data object.
    "replica_number": "<value>",

    // The absolute logical path to use for the new hard linked data object.
    // This path will point to the physical path identified by
    // tuple (logical_path, replica_number).
    "link_name": "<value>"
}
```
#### Creating a hard link
Use `irule` to execute the operation. For example, given the following:
```bash
$ ils -L
/tempZone/home/rods:
  rods              0 demoResc          507 2020-04-07.07:47 & foo
        generic    /var/lib/irods/Vault/home/rods/foo
```

We can create a hard link by running the following:
```bash
$ irule -r irods_rule_engine_plugin-hard_links-instance '{"operation": "hard_link_create", "logical_path": "/tempZone/home/rods/foo", "replica_number": "0", "link_name": "/tempZone/home/rods/bar.hl"}' null ruleExecOut
```

If there were no errors, then `ils -L` will produce the following output:
```bash
$ ils -L
/tempZone/home/rods:
  rods              0 demoResc          507 2020-04-07.07:47 & foo
        generic    /var/lib/irods/Vault/home/rods/foo
  rods              0 demoResc          507 2020-04-07.08:10 & bar.hl
        generic    /var/lib/irods/Vault/home/rods/foo
```
Notice how both data objects have a replica number of zero. Hard links are created as if the source data
object does not exist in iRODS. 

We can verify that these two data objects are hard linked to the same physical object by showing that they
have identical hard link metadata values. Here, `value` is simply a unique identifier and `units` is the
ID of the resource where the physical object rests. Notice how `value` and `units` are the same for both
data objects. All data objects sharing the same `(value, units)` pair point to the same physical object.
```bash
$ imeta ls -d foo
AVUs defined for dataObj /tempZone/home/rods/foo:
attribute: irods::hard_link
value: 63fa4580-d98e-4dec-b27b-6a4157551ebc
units: 10014
$ imeta ls -d bar.hl
AVUs defined for dataObj /tempZone/home/rods/bar.hl:
attribute: irods::hard_link
value: 63fa4580-d98e-4dec-b27b-6a4157551ebc
units: 10014
```

#### Removing a hard link
The plugin understands `irm` and `itrim`, so you are free to remove hard links with them. If there are
at least two data objects sharing the same hard link metadata, then attempting to remove one of them
triggers an unregister of that data object. The hard link metadata is removed from all data objects when
there are only two left.

### Invoking operations via the Native Rule Language
The following creates a hard link just like in the section above.
```bash
$ irule -r irods_rule_engine_plugin-irods_rule_language-instance 'hard_link_create(*lp, *rn, *ln)' '*lp=/tempZone/home/rods/foo%*rn=0%*ln=/tempZone/home/rods/bar.hl' ruleExecOut
```

