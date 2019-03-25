# ![Monarch](graphics/banner.png)

This is a series of tools for [Chaos Toolkit](https://chaostoolkit.org/) (CTK) which can perform targeted experiments
on applications deployed in [Cloud Foundry](https://www.cloudfoundry.org/).

## Available Experiments

- Block general network traffic
    - Block all incoming traffic to the application
    - Block all outgoing traffic from the application
- Block service traffic
    - Auto-detection of bound services and support for manually specified non-bound services 
    - Block all outgoing traffic from the application to one or more bound services
    - Block all incoming traffic form the application to one or more bound services
- Manipulate all network traffic from an application (including to its services)
    - Latency
    - Packet loss
    - Packet duplication
    - Packet corruption
- Impose bandwidth restrictions
    - Application download bandwidth shaping (using queuing)
    - Application upload bandwidth limiting (using policing)
- Perform network speedtest from within hosting containers
- Crash one or more random application instances
- Kill/start monit processes on hosting diego-cells


## Setup

### Build Dockerfile
It is recommended that you run Monarch with [Docker](https://www.docker.com/) which you can get
[here](https://www.docker.com/products/docker-desktop). We have had some issues with cross-platform support for the
underlying CLIs.

With docker up and running, run the following within the root of the git repository:
```bash
# FIRST Run
docker build -t monarch .
docker run -it \
    --name monarch \
    -v C:\Users\<username>\Documents\certs:/monarch/certs           # Can be a different local path or be omitted
    -v C:\Users\<username>\Documents\monarch\config:/monarch/config # and create the needed files from within.
    monarch

# Subsequent Runs
docker start -ai monarch

# Rebuild Image (You will loose information not in an attached volume)
docker container rm monarch
yes | docker image prune
# goto FIRST Run ;)
``` 

Note that both certs and config are optional and do not need to be mounted, however, even if you do not have any written
already, you should mount the volumes to prevent data loss when you destroy the container during the inevitable upgrade
process.

From within the docker image, you may now use either the python shell to interact with monarch, or chaostollkit which is
installed automatically when the image is built. You will need to login with cf-cli and bosh-cli before attempting to
use monarch.

### Install Locally
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
- `quantum`: The quantum to use when configuring qdisc perturbance. The recommended `6000` should work without issue.

Sample config.yml or `cfg` values for Chaos Toolkit.

```yaml
bosh:
  cmd: bosh2 # bosh CLI to be used
  env: bosh-lite #environment alias name 
  cf-dep: cf # Bosh deployment name
  cfdot-dc: diego_cell/0
cf:
  cmd: cf
container-port-whitelist:
 - 22
 - 2222
host-port-whitelist: []
service-whitelist:
 - logger
quantum: 6000
#services:  # custom service definitions, not needed for bound services
#  - name: google
#    host: google.com
#    ports:
#     - ['tcp', 80]
#     - ['tcp', 443]
#     - ['icmp', 'all']
```


## Usage
There are two ways you can call these scripts. The first is the Python Shell which will allow you to manually block
services or applications and then unblock them at your leisure. The second is through the `actions` and `probes` which
should be called by Chaos Toolkit.

### Chaos Toolkit Interface
If you have not installed the `monarch` package, then make sure you run Chaos Toolkit from this directory (the root of
this repository) using `python -m chaostoolkit run exp.json` or else the `monarch` module will not be found. Otherwise
just use `chaos run exp.json` from any directory.

Currently, the Chaos Toolkit interface does not support saving information about what was targeted, which should be okay
for the time being as we have yet to observe Cloud Foundry moving app instances as a result of any of these actions.
Though it is a good reason to be cautious of its use as it simply re-queries again when unblocking, so if something did
move, it will not remove the old rule in the location the app is no longer at. If you need to manually verify that all 
of the rules have been removed, you can go through each diego-cell in the Cloud Foundry deployment and run
`iptables -L | grep DROP` to see if any rules are lingering. (This script *should* be the only source of `DROP` rules).

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
    "service-whitelist": ["T-Logger"],
    "quantum": 6000
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
        "module": "monarch.pcf.actions",
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
        "module": "monarch.pcf.actions",
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
For now, there is no CLI interface, instead use an interactive python shell session. See bleow.

### From Python Shell
Example session:
```python
from monarch.pcf.config import Config
from monarch.pcf.app import App

Config().load_yaml('config/tt-stg02.yml')

app = App.discover('sys-tmo', 'ce-service-registry', 'spring-music')

app.block()
app.unblock()

app.crash_random_instance(2) # will require that you rediscover the app once CF brings a new container up
app = App.discover('sys-tmo', 'ce-service-registry', 'spring-music')

app.block_services('musicdb')
app.unblock_services()

```


## License
Monarch is open-sourced under the terms of section 7 of the Apache 2.0 license and is released AS-IS WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND.

