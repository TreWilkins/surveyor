import pytest
import sys
import os
from click.testing import CliRunner
sys.path.append(os.getcwd())
from surveyor import Surveyor
from common import Tag

@pytest.fixture
def runner():
    return CliRunner()


def test_survey_cbr(mocker):
    """
    Verify when passing `cbr` parameter, the CbResponse product is called
    """
    mocked_func = mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    Surveyor("cbr").survey()
    mocked_func.assert_called()


def test_survey_cbc(mocker):
    """
    Verify when passing 'cbc' parameter, the CbEnterpriseEdr product is called
    """
    mocked_func = mocker.patch('products.vmware_cb_enterprise_edr.CbEnterpriseEdr._authenticate')
    Surveyor("cbc").survey()
    mocked_func.assert_called_once()


def test_survey_s1(runner, mocker):
    """
    Verify when passing `s1` parameter, the SentinelOne product is called
    """
    mocked_func = mocker.patch('products.sentinel_one.SentinelOne._authenticate')
    with runner.isolated_filesystem() as temp_dir:
        cred_file_path = os.path.join(temp_dir, "test_creds.ini")
        with open(cred_file_path, 'w') as deffile:
            deffile.write("testing123")
            Surveyor(
                "s1", 
                creds_file=str(cred_file_path)
            ).survey()
        mocked_func.assert_called_once()


def test_survey_dfe(runner, mocker):
    """
    Verify when passing `dfe` parameter, the DefenderForEndpoints product is called
    """
    mocked_func = mocker.patch('products.microsoft_defender_for_endpoints.DefenderForEndpoints._authenticate')
    with runner.isolated_filesystem() as temp_dir:
        cred_file_path = os.path.join(temp_dir, "test_creds.ini")
        with open(cred_file_path, 'w') as deffile:
            deffile.write("testing123")
        Surveyor(
                "dfe", 
                creds_file=str(cred_file_path)
            ).survey()
        mocked_func.assert_called_once()


def test_survey_cortex(runner, mocker):
    """
    Verify when passing `cortex` parameter, the CortexXDR product is called
    """
    mocked_func = mocker.patch('products.cortex_xdr.CortexXDR._authenticate')
    with runner.isolated_filesystem() as temp_dir:
        cred_file_path = os.path.join(temp_dir, "test_creds.ini")
        with open(cred_file_path, 'w') as deffile:
            deffile.write("testing123")
        Surveyor(
                "cortex", 
                creds_file=str(cred_file_path)
            ).survey()
        mocked_func.assert_called_once()


def test_custom_query(mocker):
    """
    Verify when a query is passed, it is logged and an EDR product is called
    """
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_process_search = mocker.patch('products.vmware_cb_response.CbResponse.process_search')
    Surveyor("cbr").survey(query="SELECT * FROM processes")
    mocked_process_search.assert_called_once_with(Tag('query'), {}, 'SELECT * FROM processes')


def test_def_file(mocker):
    """
    Verify when a definition file is passed, it is logged and an EDR product is called
    """
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')

    Surveyor("cbr").survey(definitions={"ProgramA":{"process_name":["test.exe"]}}, label="test_deflist")
    mocked_nested_process_search.assert_called_once_with(
        Tag('ProgramA', 'test_deflist'), 
        {"process_name":["test.exe"]}, 
        {}
        )


def test_def_file_with_base_query(mocker):
    """
    Verify when a definition file is passed, it is logged and an EDR product is called
    """
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    Surveyor("cbr").survey(definitions={"ProgramA":{"process_name":["test.exe"]}}, days=5, hostname="workstation1", username="admin", label="test_deflist")
    mocked_nested_process_search.assert_called_once_with(
        Tag('ProgramA', 'test_deflist'), 
        {"process_name":["test.exe"]}, 
        {'days':5, 'hostname':'workstation1', 'username':'admin'}
        )


def test_ioc_file(mocker):
    """
    Verify if an IOC file is passed, it is logged and an EDR product is called
    """
    mocked_func = mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')

    Surveyor("cbr").survey(ioc_list=["127.0.0.1"], ioc_type="ipaddr", label="test_ioc_list")
    mocked_func.assert_called_once()
    mocked_nested_process_search.assert_called_once_with(Tag(f'IOC - [\'127.0.0.1\']', 'test_ioc_list'), {'ipaddr':['127.0.0.1']}, {})


def test_ioc_file_with_base_query(mocker):
    """
    Verify if an IOC file is passed, it is logged and an EDR product is called
    """
    mocked_func = mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')

    Surveyor("cbr").survey(ioc_list=["127.0.0.1"], ioc_type="ipaddr", days=5, hostname="workstation1", username="admin", label="test_ioc_list")
    mocked_func.assert_called_once()
    mocked_nested_process_search.assert_called_once_with(
        Tag(f'IOC - [\'127.0.0.1\']', 'test_ioc_list'), 
        {'ipaddr':['127.0.0.1']}, 
        {'days':5, 'hostname':'workstation1', 'username':'admin'}
        )


def test_unsupported_option():
    with pytest.raises(Exception) as e_info:
        Surveyor("cbr").survey(asdfasdfasdfasdf="test")
        assert "got an unexpected keyword argument" in e_info


def test_dependent_ioc_args():
    with pytest.raises(Exception) as e_info:
        Surveyor("cbr").survey(ioc_file=["127.0.0.1"])
        assert "iocfile requires ioctype" in e_info


def test_mutually_exclusive_days_mins():
    with pytest.raises(Exception) as e_info:
        Surveyor("cbr").survey(days=3, minutes=4)
        assert "days and minutes are mutually exclusive" in str(e_info)


def test_base_query_filters_with_query(mocker):
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_process_search = mocker.patch('products.vmware_cb_response.CbResponse.process_search')
    Surveyor("cbr").survey(query="SELECT * FROM processes", days=5, hostname="workstation1", username="admin")
    mocked_process_search.assert_called_once_with(
        Tag('query'), 
        {'days':5, 'hostname':'workstation1','username':'admin'}, 
        'SELECT * FROM processes'
        )


def test_sigma_rule(mocker):
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')


    sigmarule="""title: Test sigma rule
id: 5fd18e43-749c-4bae-93b6-d46e1f27062e
description: Test sigma rule
logsource:
    category: process_creation
detection:
    selection:
        - Image: 'curl.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine"""
    Surveyor("cbr").survey(sigma_rule=sigmarule, label='Sigma Rule')
    mocked_nested_process_search.assert_called_once_with(Tag('Test sigma rule - 5fd18e43-749c-4bae-93b6-d46e1f27062e', 'Sigma Rule'), {"query":["process_name:curl.exe"]}, {})


def test_sigma_rule_with_base_query(mocker):
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')

    sigmarule="""title: Test sigma rule
id: 5fd18e43-749c-4bae-93b6-d46e1f27062e
description: Test sigma rule
logsource:
    category: process_creation
detection:
    selection:
        - Image: 'curl.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine"""
    Surveyor("cbr").survey(sigma_rule=sigmarule, days=5, hostname="workstation1", username="admin", label='Sigma Rule')
    mocked_nested_process_search.assert_called_once_with(Tag('Test sigma rule - 5fd18e43-749c-4bae-93b6-d46e1f27062e', 'Sigma Rule'), {"query":["process_name:curl.exe"]}, {'username':'admin', 'hostname':'workstation1','days':5 })