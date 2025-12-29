# vROPS (Aria Operations) REST API Information

## Common Endpoints

### Authentication
- POST `/suite-api/api/auth/token/acquire` - Acquire authentication token
- GET `/suite-api/api/auth/token` - Verify token
- DELETE `/suite-api/api/auth/token` - Revoke token

### Inventory and Resources
- GET `/suite-api/api/resources` - Get all resources
- GET `/suite-api/api/resources/types` - Get resource types
- GET `/suite-api/api/resources/relationships` - Get resource relationships

### Resource Types for VMware Infrastructure
- Resource Type: `ClusterComputeResource` - VMware clusters
- Resource Type: `NetworkEdge appliance` - NSX-T edge nodes
- Resource Type: `NSX Manager` - NSX-T managers

### Property Queries
- POST `/suite-api/api/properties` - Query resource properties
- GET `/suite-api/api/resources/relationships` - Get resource relationships

## Authentication
vROPS typically uses either:
1. Username/password authentication
2. Token-based authentication
3. Basic authentication

## Common Resource Properties
- `name` - Resource name
- `identifier` - Unique resource identifier
- `resourceKey.name` - Resource display name
- `resourceStatus` - Current status of resource
- `adapterKindKey` - Type of adapter
- `resourceKindKey` - Kind of resource