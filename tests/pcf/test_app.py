# Copyright 2019 T-Mobile US, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import os
from functools import partial
from tempfile import TemporaryDirectory

import pytest
import requests
from requests import ReadTimeout

from monarch.pcf.app import find_application_guid, find_application_routes, App
from monarch.pcf.config import Config
from monarch.pcf.util import bosh_login, cf_login, cf_target
from monarch.util import run_cmd, curl_ping, percent_diff, smart_average

get = partial(requests.get, timeout=30)


def assert_cmd(*args, **kwargs):
    rcode, stdout, stderr = run_cmd(*args, **kwargs)
    assert rcode == 0
    return stdout, stderr


@pytest.fixture(scope='session')
def cfg():
    cfg = Config()
    cfg.load_yaml('tests/config/app_test.yml')
    yield cfg


@pytest.fixture(scope='module')
def url():
    cfg = Config()
    depcfg = cfg['testing']

    push_app = bool(depcfg.get('push-app'))

    if push_app:  # got to push an app before we get the URL
        start_dir = os.getcwd()
        with TemporaryDirectory() as td:
            print("Downloading Spring Music")
            assert_cmd(['git clone https://github.com/cloudfoundry-samples/spring-music.git', td], timeout=60*2)
            os.chdir(td)
            assert_cmd('git checkout 963d307f9c0da020545d13c947ad6d5472e29c94')

            print("Building Spring Music")
            assert_cmd('./gradlew clean assemble', timeout=60*5)

            print("Deploying Spring Music...")
            assert_cmd([cfg['cf']['cmd'], 'create-service', depcfg['db-market-name'], depcfg['db-plan'],
                        depcfg['db-instance-name']])
            assert_cmd([cfg['cf']['cmd'], 'push', depcfg['appname']], timeout=60*5)
            assert_cmd([cfg['cf']['cmd'], 'bind-service', depcfg['appname'], depcfg['db-instance-name']])
            assert_cmd([cfg['cf']['cmd'], 'restage', depcfg['appname']], timeout=60*5)
            os.chdir(start_dir)

    routes = find_application_routes(find_application_guid(depcfg['appname']))
    url = routes[0]
    yield url

    if push_app:
        print("Tearing down Spring Music...")
        assert_cmd([cfg['cf']['cmd'], 'delete -f -r', depcfg['appname']])
        assert_cmd([cfg['cf']['cmd'], 'delete-service -f', depcfg['db-instance-name']])


@pytest.fixture(scope='module')
def app():
    cfg = Config()['testing']
    app = App.discover(cfg['org'], cfg['space'], cfg['appname'])
    yield app
    if app:
        app.undo_all()

@pytest.mark.incremental
class TestApp:
    @pytest.mark.usefixtures('cfg')
    def test_bosh_login(self):
        rcode, _, _ = bosh_login()
        assert rcode == 0

    def test_cf_login(self, cfg):
        rcode, _, _ = cf_login()
        assert rcode == 0
        assert cf_target(cfg['testing']['org'], cfg['testing']['space']) == 0

    @pytest.mark.usefixtures('url')
    def test_app_discovery(self, app, cfg):
        cfg = cfg['testing']
        assert app.org == cfg['org']
        assert app.space == cfg['space']
        assert app.name == cfg['appname']
        assert len(app.services) == 1
        mysql = app.services[0]
        assert mysql['type'] == cfg['db-market-name']
        assert mysql['name'] == cfg['db-instance-name']
        assert 'user' in mysql
        assert 'password' in mysql
        assert len(mysql['hosts']) > 0
        assert len(app.instances) == 1

    def test_block_traffic(self, app, url):
        url = 'http://{}/albums'.format(url)
        assert get(url).status_code == 200

        # block and make sure traffic does not reach the app
        assert app.block(direction='both') == 0
        # TODO: Verify this does not reach the app (can't check logs since app does not log this info)
        received_error_code_while_blocked = get('{}/albums'.format(url)).status_code >= 400
        app.unblock()

        assert received_error_code_while_blocked
        assert get(url).status_code == 200

    def test_block_service(self, app, cfg, url):
        url = 'http://{}/albums'.format(url)
        assert get(url).status_code == 200
        assert app.block_services([cfg['testing']['db-instance-name']], direction='both') == 0

        try:
            timeout_occurred = False
            get(url)
        except ReadTimeout:
            timeout_occurred = True

        app.unblock_services()
        assert get(url).status_code == 200
        assert timeout_occurred

    def test_manipulate_network(self, app, url):
        url += '/albums'
        PING_COUNT = 20
        LATENCY = 100  # NOTE: this value will not add an exact amount because the curl_ping uses multiple packets.
        ALLOWANCE = 0.2  # 20 percent

        base_rtt = curl_ping(url, count=PING_COUNT)
        assert app.manipulate_network(latency=LATENCY) == 0
        altered_rtt = curl_ping(url, count=PING_COUNT)
        app.unmanipulate_network()
        final_rtt = curl_ping(url, count=PING_COUNT)

        print('base_rtt: {}'.format(base_rtt))
        print('altered_rtt {}'.format(altered_rtt))
        print('final_rtt {}'.format(final_rtt))
        base_rtt = smart_average(base_rtt['times'])
        altered_rtt = smart_average(altered_rtt['times'])
        final_rtt = smart_average(final_rtt['times'])

        # make sure the base values are smilier (use percent difference)
        assert abs(percent_diff(base_rtt, final_rtt)) < ALLOWANCE

        # make sure the altered ping is larger
        assert altered_rtt > base_rtt
        assert abs(percent_diff(base_rtt, altered_rtt)) > ALLOWANCE

    def test_speedtest(self, app):
        assert app.instances[0].perform_speedtest()

    def test_shape_network(self, app, url):
        url += '/albums'
        PING_COUNT = 10
        ALLOWANCE = 0.2

        # TODO: make sure it is not just adding latency
        base_rtt = curl_ping(url, count=PING_COUNT)
        assert app.shape_network(2000, 2000) == 0
        altered_rtt = curl_ping(url, count=PING_COUNT)
        app.unmanipulate_network()
        final_rtt = curl_ping(url, count=PING_COUNT)

        print('base_rtt: {}'.format(base_rtt))
        print('altered_rtt {}'.format(altered_rtt))
        print('final_rtt {}'.format(final_rtt))
        base_rtt = smart_average(base_rtt['times'])
        altered_rtt = smart_average(altered_rtt['times'])
        final_rtt = smart_average(final_rtt['times'])

        # make sure the base values are smilier (use percent difference)
        assert abs(percent_diff(base_rtt, final_rtt)) < ALLOWANCE

        # make sure the altered ping is larger
        assert altered_rtt > base_rtt
        assert abs(percent_diff(base_rtt, altered_rtt)) > ALLOWANCE
