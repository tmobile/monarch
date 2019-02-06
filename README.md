# Monarch
This is a series of tools for [Chaos Toolkit](https://chaostoolkit.org/) which can perform targeted experiments
on application deployed in [Cloud Foundry](https://www.cloudfoundry.org/) applications their bound services.

## Setup

### Install
To be used from your experiment, this package must first be installed in the Python environment where
[chaostoolkit](https://chaostoolkit.org/) already exists. This package requires at least
[Python](https://www.python.org/) version 3.5 (3.6 if using the chaostoolkit interfaces directly), so translate `python`
as `python3` or `pyhton3.5` as appropriate for your OS.

From within the source, run:  

```bash
sudo python setup.py install
```

Or to install for just your user:

```bash
python setup.py install --user
```

Now you should be able to import the package.

```python
import monarch
print(monarch.__version__)
```


### Third-Party CLI Setup
In order to run the script, it will require that you have the
[Cloud Foundry CLI](https://docs.cloudfoundry.org/cf-cli/install-go-cli.html) installed and the
[BOSH CLI](https://bosh.io/docs/cli-v2-install/) installed. You will also need to be logged in to the Cloud Foundry CLI 
as a user with permission to access all apps which are to be targeted and logged in as and you will need to be login as
an admin with the BOSH CLI. This is because the script requires ssh access to the bosh vms to make its changes and also
prevents applications from needing SSH enabled.


### Configuration File
Once the CLIs are ready, create (or modify the existing) configuration file. This file is only necessary for CLI use as
it is included within the experiments for Chaos Toolkit. 

- `bosh`: Information about the bosh cli and environment
    - `cmd`: The bosh-cli command.
    - `env`: The environment name for the cf deployment (`-e env`).
    - `cf-dep`: The cloud foundry deployment in the bosh environment.
    - `cfdot-dc`: The diego-cell to use for `cfdot` queries.
- `cf`: Information about the cf cli and environment
    - `cmd`: The cf-cli command.
- `container-port-whitelist`: List of node ports which should be ignored. These are the external ports on the
diego-cells.
- `service-whitelist`: List of service types which should be ignored. These must be the names displayed in the cf-cli
marketplace.

Sample config.yml or `cfg` values for Chaos Toolkit.

```yaml
bosh:
  cmd: bosh2
  env: bosh-lite
  cf-dep: cf
  cfdot-dc: diego-cell/0
cf:
  cmd: cf
container-port-whitelist:
 - 22
 - 2222
host-port-whitelist: []
service-whitelist:
 - logger
```


## Usage
There are two ways you can call these scripts. The first is the CLI which will allow you to manually block a
services or applications and then unblock them at your leisure. The second is through the `actions` and `probes` which
should be called by Chaos Toolkit. (Chaos Toolkit should **never** call the CLI interface).

Presently, the CLI and Chaos Toolkit interfaces are not directly compatible due to the added filtering options in the
Chaos Toolkit version and the anticipated support for this being run as a service. Eventually the Chaos Toolkit
interface will save to a database what was attacked as the CLI currently saves to a JSON file. Until that time, the
CLI interface is stateful saving to the targeted file and the Chaos Toolkit interface is stateless re-querying each
time for hosts and services. As we have yet to observe Cloud Foundry or moving application containers, this *should* not
be an issue.

### Chaos Toolkit Interface
If you have not installed the `monarch` package, then make sure you run Chaos Toolkit from this directory (the root of
this repository) using `pyhton -m chaostoolkit run exp.json` or else the `monarch` module will not be found. Otherwise
just use `chaos run exp.json` from any directory.

Currently, the Chaos Toolkit interface does not support saving information about what was targeted, which should be okay
for the time being as we have yet to observe Cloud Foundry moving app instances as a result of any of these actions.
Though it is a good reason to be cautious of its use as it simply re-queries again when unblocking, so if something did
move, it will not remove the old rule in the location the app is not longer at. If you need to manually verify that all 
of the rules have been removed, you can go through each diego-cell in the Cloud Foundry deployment and run
`iptables -L | grep DROP` to see if any rules are lingering. (This scrip *should* be the only source of `DROP` rules).

The following is a sample, Chaos-Toolkit experiment file to block all traffic to the application.

```json
{
  "version": "0.1.0",
  "title": "Blocking spring-music makes it unreachable.",
  "description": "This is a testing experiment to verify the script's block traffic function works.",
  "tags": ["cloudfoundry", "bosh", "springboot"],
  "configuration": {
    "TODO": "Some of this needs to be part of the application configuration since the user of this would not know what the cli commands are for instance.",
    "bosh": {
      "cmd": "bosh2",
      "env": "tt-stg02",
      "cf-dep": "cf-da0ba81cb255ad93a508",
      "cfdot-dc": "diego_cell/0"
    },
    "cf": {
      "cmd": "cf"
    },
    "container-port-whitelist": [22, 2222],
    "host-port-whitelist": [],
    "service-whitelist": ["T-Logger"]
  },
  "steady-state-hypothesis": {
    "title": "We can access the application and other neighboring applications (This should fail because we block all traffic)",
    "probes": [
      {
        "type": "probe",
        "name": "spring-music-responds",
        "tolerance": 200,
        "provider": {
          "type": "http",
          "url": "http://spring-music-interested-bonobo.apps.tt-stg02.cf.t-mobile.com/"
        }
      },
      {
        "type": "probe",
        "name": "spring-music2-responds",
        "tolerance": 200,
        "provider": {
          "type": "http",
          "url": "http://spring-music2-lean-sable.apps.tt-stg02.cf.t-mobile.com/"
        }
      }
    ]
  },
  "method": [
    {
      "type": "action",
      "name": "block-traffic",
      "provider": {
        "type": "python",
        "module": "monarch.actions",
        "func": "block_traffic",
        "arguments": {
          "org": "sys-tmo",
          "space": "test",
          "appname": "spring-music"
        }
      }
    }
  ],
  "rollbacks": [
    {
      "type": "action",
      "name": "unblock-traffic",
      "provider": {
        "type": "python",
        "module": "monarch.actions",
        "func": "unblock_traffic",
        "arguments": {
          "org": "sys-tmo",
          "space": "test",
          "appname": "spring-music"
        }
      }
    }
  ]
}
``` 

### CLI Interface
```commandline
usage: cli.py [-h] [-b TO_BLOCK]
              [--block-app | --crash-instance | --block-services | --unblock-all | --discover]
              [--config PATH] [--targeted PATH]
              org space app

Block Cloud Foundry Applications or their Services.

positional arguments:
  org                   Cloud Foundry Organization the Application is in.
  space                 Cloud Foundry Space the Application is in.
  app                   Name of the application in Cloud Foundry.

optional arguments:
  -h, --help            show this help message and exit
  -b TO_BLOCK, --block TO_BLOCK
                        Block access to a service.
  --block-app           Block access to the application.
  --crash-instance      Crash a random app instance.
  --block-services      Block the app from accessing any of its bound
                        services.
  --unblock-all         Unblock the app and its services.
  --discover            Discover the application hosts and bound service
                        information.
  --config PATH         Specify an alternative config path.
  --targeted PATH       Specify an alternative storage location for targeted
                        applications and services.
```
