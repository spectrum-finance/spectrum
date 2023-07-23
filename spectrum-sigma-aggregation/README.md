# Test node for sigma-aggregation


## Form a new committee

To form a new committee we must first know the IP address and ports of each participating node. This information should be listed in a YAML file with the following format:
```yaml
members:
- - 0 # Node index, must be unique
  - ip_address: 127.0.0.1
    rest_api_port: 8000
    peer_port: 3000
- - 1
  - ip_address: 127.0.0.1
    rest_api_port: 8001
    peer_port: 3001
- - 2
  - ip_address: 127.0.0.1
    rest_api_port: 8002
    peer_port: 3002
- - 3
  - ip_address: 127.0.0.1
    rest_api_port: 8003
    peer_port: 3003
```

The above example is for a committee of 4 nodes.

To run just type
```
./spectrum-sigma-aggregation generate-new-committee --config-path path/to/yaml
```

The binary then generates the following YAML files:
 - `committee.yaml`: full details of the committee, to be used when orchestrating sigma-aggregations
 - `node_config_0.yaml`: configuration file for node with index 0
 - `node_config_1.yaml`: configuration file for node with index 1
 - ...
 
## Running a node

Use the following command to run a node:
```
./spectrum-sigma-aggregation run-node --config-path path/to/node_config_*.yaml
```

where `node_config_*.yaml` was created by the `generate-new-committee` action.

## Initialise orchestration of a sigma-aggregation

Use the following command to create a template YAML file orchestrate aggregation:
```
./spectrum-sigma-aggregation generate-orchestration-template --message "I am bob" --threshold-numerator 4 --threshold-denominator 4
```

This generates a YAML file `orchestrate_template.yaml`:
```yaml
message:
  # Blake2B encoded message. Omitted here
public_seed:
  # Generated. Omitted here.

threshold:
  num: 4
  denom: 4
delayed_nodes: []
byzantine_nodes: []
```

You can alter the parameters to delay nodes and make Byzantine as follows:

```yaml
delayed_nodes:
- node_ix: 2
  delay_in_milliseconds: 200
byzantine_nodes: [ 1 ]
```

## Orchestrating a sigma-aggregation


```
./spectrum-sigma-aggregation orchestrate-aggregation --orchestration-path orchestrate.yaml --committee-data-path committee.yaml
```