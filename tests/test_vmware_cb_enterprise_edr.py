import pytest
import sys
import os
import logging
import json
from datetime import datetime, timedelta
import random
from unittest.mock import patch
sys.path.append(os.getcwd())
from products.vmware_cb_enterprise_edr import CbEnterpriseEdr
from common import Tag

class MockProcResult():
    def get_details(self):
        random_num = random.randint(1, 1000)
        return {'device_name': f'workstation{random_num}', 'process_username':[f'username{random_num}'], 'process_name':f'proc{random_num}', 'process_cmdline':[f'cmdline{random_num}'], 'device_timestamp': f'ts{random_num}', 'process_guid': f'guid{random_num}'}


@pytest.fixture
def cbc_product():
    with patch.object(CbEnterpriseEdr, "__init__", lambda x, y: None):
      return CbEnterpriseEdr(None)


def test_build_query_with_supported_field(cbc_product : CbEnterpriseEdr):
    filters = {
        'hostname': 'workstation1',
        'username': 'admin'
    }

    cbc_product._device_group = ['accounting dept']
    cbc_product._device_policy = ['strict']

    result = ' '.join(cbc_product.build_query(filters)._raw_query)

    assert result == 'device_name:workstation1 process_username:admin (device_group:"accounting dept") (device_policy:"strict")'


def test_build_query_with_days(cbc_product: CbEnterpriseEdr):
    filters = {
        'days': 7
    }

    cbc_product._device_group = None
    cbc_product._device_policy = None

    result = ' '.join(cbc_product.build_query(filters)._raw_query)

    assert result.startswith('device_timestamp:[')
    assert result.endswith(']')
    assert ' TO ' in result
    timespan = result.replace('device_timestamp:[','').replace(']','').split(' TO ')
    time_format = "%Y-%m-%dT%H:%M:%SZ"
    assert datetime.strptime(timespan[1], time_format) - timedelta(days=7) == datetime.strptime(timespan[0], time_format)


def test_build_query_with_min(cbc_product: CbEnterpriseEdr):
    filters = {
        'minutes': 30
    }

    cbc_product._device_group = None
    cbc_product._device_policy = None

    result = ' '.join(cbc_product.build_query(filters)._raw_query)

    assert result.startswith('device_timestamp:[')
    assert result.endswith(']')
    assert ' TO ' in result
    timespan = result.replace('device_timestamp:[','').replace(']','').split(' TO ')
    time_format = "%Y-%m-%dT%H:%M:%SZ"
    assert datetime.strptime(timespan[1], time_format) - timedelta(minutes=30) == datetime.strptime(timespan[0], time_format)


def test_build_query_with_unsupported_field(cbc_product : CbEnterpriseEdr):
    filters = {
      "useless key": "asdfasdasdf"
    }

    cbc_product._device_group = None
    cbc_product._device_policy = None
    cbc_product.log = logging.getLogger('pytest_surveyor')

    result = cbc_product.build_query(filters)._raw_query

    assert result == None


def test_divide_chunks(cbc_product : CbEnterpriseEdr):
    entries = ['a','b','c','d','e']
    expected_results = [['a','b','c'],['d','e']]
    count = 3
    i = 0

    results = cbc_product.divide_chunks(l=entries, n=count)
    for item in results:
        assert item == expected_results[i]
        i += 1


def test_process_search(cbc_product : CbEnterpriseEdr, mocker):
    cbc_product._device_group = None
    cbc_product._device_policy = None
    cbc_product._results = {}
    mocker.patch.object(cbc_product, 'perform_query')
    cbc_product.process_search(Tag('test_field'), {}, 'process_name:cmd.exe')
    cbc_product.perform_query.assert_called_once_with(Tag('test_field'), {}, 'process_name:cmd.exe') # type:ignore


def test_nested_process_search(cbc_product : CbEnterpriseEdr, mocker):
    with open(os.path.join(os.getcwd(), 'tests', 'data', 'cbc_surveyor_testing.json')) as f:
        programs = json.load(f)
    
    cbc_product.log = logging.getLogger('pytest_surveyor')
    cbc_product._sensor_group = None # type:ignore
    cbc_product._results = {}
    cbc_product._conn = mocker.Mock()
    with patch.object(cbc_product, 'perform_query') as perform_query:

        expected_calls = [
            mocker.call(Tag('field_translation'), {}, '((process_name:notepad.exe) OR (netconn_ipv4:127.0.0.1) OR (process_cmdline:MiniDump) OR (process_publisher:Microsoft) OR (netconn_domain:raw.githubusercontent.com) OR (process_internal_name:powershell) OR (hash:asdfasdfasdfasdf) OR (hash:zxcvzxcvzxcv) OR (regmod_name:HKLM) OR (netconn_port:80))'),
            mocker.call(Tag('multiple_values'), {}, '(process_name:svchost.exe OR process_name:cmd.exe)'),
            mocker.call(Tag('single_query'), {}, '(process_name:rundll.exe)'),
            mocker.call(Tag('multiple_query'), {}, '((process_cmdline:-enc) OR (modload_name:malware.dll))')
        ]

        for program, criteria in programs.items():
            cbc_product.nested_process_search(Tag(program), criteria, {})
        perform_query.assert_has_calls(expected_calls, any_order=True)
        

def mocked_query_return(full_query: str):
    return [
        MockProcResult(),
        MockProcResult(),
        MockProcResult()
    ]