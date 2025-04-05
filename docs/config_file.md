## DistributedCacheFS Configuration File (`config.json`)

This document describes the structure and options for the JSON configuration file used by `DistributedCacheFS`.

### Overview

The configuration file is a JSON object containing settings for a single node within the distributed file system. It defines the node's identity, the origin data source, global operational parameters, and the cache storage tiers it will manage.

### Top-Level Structure

The root JSON object must contain the following keys:

-   `node_id` (string, **required**): A unique identifier for this node within the distributed system. Must be non-empty.
-   `origin` (object, **required**): Defines the origin filesystem source where the original data resides.
-   `global_settings` (object, *optional*): Contains global configuration parameters for the node.
-   `cache_tiers` (array, **required**): An array defining the cache storage tiers managed by this node. This array must contain at least one cache tier definition object.

### `origin` Object

This required object defines the source of the original data.

-   `type` (string, **required**): Specifies the type of the origin filesystem.
    -   Allowed values:
        -   `"local"`: The origin is a local filesystem path accessible directly by this node. (Currently the only supported type).
-   `path` (string, **required**): The absolute or relative filesystem path to the root directory of the origin data source. Must be non-empty.

### `global_settings` Object

This optional object contains general settings for the node's operation.

-   `log_level` (string, *optional*, default: `"info"`): Sets the logging verbosity.
    -   Allowed values: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`, `"critical"` (or `"fatal"`), `"off"`.
-   `mdns_service_name` (string, *optional*, default: `"_dcachefs._tcp"`): The mDNS service name used for node discovery (if applicable).
-   `listen_port` (number, *optional*, default: `9876`): The network port the node listens on for communication with other nodes.
-   *(Note: Cache-specific global settings might be added here in the future)*.

### `cache_tiers` Array

This required array contains one or more objects, each defining a cache storage tier managed by this node. Each object represents a `CacheTierDefinition` and has the following keys:

-   `path` (string, **required**): The absolute or relative filesystem path to the directory used for this cache tier. Must be non-empty.
-   `tier` (number, **required**): An integer representing the priority tier of this cache storage. Lower numbers indicate higher priority (checked first for reads, potentially written to first). Must be 0 or greater.
-   `type` (string, **required**): Specifies the type of storage used for this cache tier.
    -   Allowed values:
        -   `"local"`: This cache storage is exclusively used by this node.
        -   `"shared"`: This cache storage is potentially shared or synchronized with other nodes. *(Currently not fully implemented)*.

#### Fields for `type: "shared"`

If `type` is set to `"shared"`, the following additional fields are required:

-   `policy` (string, **required**): Defines how the shared cache storage is managed.
    -   Allowed values:
        -   `"sync"`: Data is expected to be synchronized across all nodes using this shared storage (e.g., a shared NFS mount). The full capacity is available.
        -   `"divide"`: The storage space is logically divided among nodes participating in the `share_group`. Requires size constraints.
-   `share_group` (string, **required**): An identifier grouping nodes that share this cache storage resource. Cannot be empty.

#### Fields for `policy: "divide"` (within `type: "shared"`)

If `type` is `"shared"` and `policy` is `"divide"`, the following optional fields can be used to constrain the space allocated to this node:

-   `min_size_gb` (number, *optional*): The minimum size (in Gigabytes) this node attempts to claim from the shared divided storage. Must be non-negative if present.
-   `max_size_gb` (number, *optional*): The maximum size (in Gigabytes) this node is allowed to use from the shared divided storage. Must be greater than or equal to `min_size_gb` if both are specified.

#### Fields for `type: "local"`

If `type` is set to `"local"`, the fields `policy`, `share_group`, `min_size_gb`, and `max_size_gb` **must not** be present.

### Example `config.json`

```json
{
  "node_id": "cache-node-alpha",
  "origin": {
    "type": "local",
    "path": "/path/to/origin/data"
  },
  "global_settings": {
    "log_level": "debug",
    "listen_port": 9877
  },
  "cache_tiers": [
    {
      "path": "/mnt/nvme_cache",
      "tier": 0,
      "type": "local"
    },
    {
      "path": "/mnt/hdd_cache",
      "tier": 1,
      "type": "local"
    }
    // Example shared tier definitions (currently not fully implemented)
    /*
    ,{
      "path": "/mnt/shared_nfs",
      "tier": 2,
      "type": "shared",
      "policy": "sync",
      "share_group": "nfs_group_1"
    },
    {
      "path": "/mnt/ceph_pool_cache",
      "tier": 1,
      "type": "shared",
      "policy": "divide",
      "share_group": "ceph_cache_users",
      "min_size_gb": 100.5,
      "max_size_gb": 500.0
    }
    */
  ]
}
```

### Validation Notes
-   The `node_id` must be non-empty.
-   The `origin` object must be present and contain a valid `type` (currently only `"local"`) and a non-empty `path`.
-   The `cache_tiers` array must not be empty.
-   Each cache tier definition must have a non-empty `path`, a non-negative `tier`, and a valid `type`.
-   Cache tier definitions with `type: "shared"` must include a valid `policy` and a non-empty `share_group`.
-   Cache tier definitions with `type: "local"` must *not* include `policy`, `share_group`, `min_size_gb`, or `max_size_gb`.
-   If `policy` is `"divide"`, `min_size_gb` (if present) must be non-negative, and `max_size_gb` (if present) must be >= `min_size_gb` (if present).