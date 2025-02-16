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


def test_def_file(runner, mocker):
    """
    Verify when a definition file is passed, it is logged and an EDR product is called
    """
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    with runner.isolated_filesystem() as temp_dir:
        def_file_path = os.path.join(temp_dir, "test_deffile.json")
        with open(def_file_path, 'w') as deffile:
            deffile.write("""{"ProgramA":{"process_name":["test.exe"]}}""")
        Surveyor("cbr").survey(def_file=def_file_path)
        mocked_nested_process_search.assert_called_once_with(Tag('ProgramA', 'test_deffile'), {"process_name":["test.exe"]}, {})


def test_def_file_with_base_query(runner, mocker):
    """
    Verify when a definition file is passed, it is logged and an EDR product is called
    """
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    filter_args = ['--days', '5', '--hostname', 'workstation1', '--username', 'admin']
    with runner.isolated_filesystem() as temp_dir:
        def_file_path = os.path.join(temp_dir, "test_deffile.json")
        with open(def_file_path, 'w') as deffile:
            deffile.write("""{"ProgramA":{"process_name":["test.exe"]}}""")
        Surveyor("cbr").survey(def_file=def_file_path, days=5, hostname="workstation1", username="admin")
        mocked_nested_process_search.assert_called_once_with(Tag('ProgramA', 'test_deffile'), {"process_name":["test.exe"]}, {'days':5, 'hostname':'workstation1', 'username':'admin'})


def test_def_dir(runner, mocker):
    """
    Verify when a definition directory is passed, it is logged and an EDR product is called
    """
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    with runner.isolated_filesystem() as temp_dir:
        def_file_path1 = os.path.join(temp_dir, "test_deffile1.json")
        def_file_path2 = os.path.join(temp_dir, "test_deffile2.json")
        with open(def_file_path1, 'w') as deffile:
            deffile.write("""{"ProgramA":{"process_name":["test1.exe"]}}""")
        with open(def_file_path2, 'w') as deffile:
            deffile.write("""{"ProgramB":{"process_name":["test2.exe"]}}""")

        expected_calls = [mocker.call(Tag('ProgramA', 'test_deffile1'),{"process_name":["test1.exe"]}, {}), 
                          mocker.call(Tag('ProgramB', 'test_deffile2'),{"process_name":["test2.exe"]}, {})]
        Surveyor("cbr").survey(def_dir=temp_dir)
        mocked_nested_process_search.assert_has_calls(expected_calls, any_order=True)


def test_def_dir_with_base_query(runner, mocker, capsys):
    """
    Verify when a definition directory is passed, it is logged and an EDR product is called
    """
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    filter_args = ['--days', '5', '--hostname', 'workstation1', '--username', 'admin']
    with runner.isolated_filesystem() as temp_dir:
        def_file_path1 = os.path.join(temp_dir, "test_deffile1.json")
        def_file_path2 = os.path.join(temp_dir, "test_deffile2.json")
        with open(def_file_path1, 'w') as deffile:
            deffile.write("""{"ProgramA":{"process_name":["test1.exe"]}}""")
        with open(def_file_path2, 'w') as deffile:
            deffile.write("""{"ProgramB":{"process_name":["test2.exe"]}}""")

        expected_calls = [mocker.call(Tag('ProgramA', 'test_deffile1'),{"process_name":["test1.exe"]}, {'days':5, 'hostname':'workstation1', 'username':'admin'}), 
                          mocker.call(Tag('ProgramB', 'test_deffile2'),{"process_name":["test2.exe"]}, {'days':5, 'hostname':'workstation1', 'username':'admin'})]
        Surveyor("cbr").survey(def_dir=temp_dir,days=5, hostname="workstation1", username="admin")
        mocked_nested_process_search.assert_has_calls(expected_calls, any_order=True)


def test_invalid_def_file(mocker, capsys):
    """
    Verify if a non-existent definition file is passed, it is logged and nothing is passed to the EDR product
    """
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    Surveyor("cbr").survey(def_file="nonexistent.json")
    mocked_nested_process_search.assert_not_called()


def test_invalid_sigma_rule(mocker):
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    with pytest.raises(Exception) as e_info:
        Surveyor("cbr").survey(sigma_rule="nonexistent.yml")
    assert "Supplied --sigmarule is not a file" in str(e_info)
    mocked_nested_process_search.assert_not_called()


def test_invalid_sigma_dir(mocker):
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    with pytest.raises(Exception) as e_info:
        Surveyor("cbr").survey(sigma_dir="./nonexistent_dir")
    assert "Supplied --sigmadir is not a directory" in str(e_info)
    mocked_nested_process_search.assert_not_called()


def test_ioc_file(runner, mocker):
    """
    Verify if an IOC file is passed, it is logged and an EDR product is called
    """
    mocked_func = mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    with runner.isolated_filesystem() as temp_dir:
        ioc_file_path = os.path.join(temp_dir, "ioc_list.txt")
        with open(ioc_file_path, 'w') as deffile:
            deffile.write("127.0.0.1")
        Surveyor("cbr").survey(ioc_file=ioc_file_path, ioc_type="ipaddr")
        mocked_func.assert_called_once()
        mocked_nested_process_search.assert_called_once_with(Tag(f'IOC - {ioc_file_path}', 'ioc_list.txt'), {'ipaddr':['127.0.0.1']}, {})


def test_ioc_file_with_base_query(runner, mocker):
    """
    Verify if an IOC file is passed, it is logged and an EDR product is called
    """
    mocked_func = mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    with runner.isolated_filesystem() as temp_dir:
        ioc_file_path = os.path.join(temp_dir, "ioc_list.txt")
        with open(ioc_file_path, 'w') as deffile:
            deffile.write("127.0.0.1")
        Surveyor("cbr").survey(ioc_file=ioc_file_path, ioc_type="ipaddr", days=5, hostname="workstation1", username="admin")
        mocked_func.assert_called_once()
        mocked_nested_process_search.assert_called_once_with(Tag(f'IOC - {ioc_file_path}', 'ioc_list.txt'), {'ipaddr':['127.0.0.1']}, {'days':5, 'hostname':'workstation1', 'username':'admin'})


def test_unsupported_option():
    with pytest.raises(Exception) as e_info:
        Surveyor("cbr").survey(asdfasdfasdfasdf="test")
        assert "got an unexpected keyword argument" in e_info


def test_dependent_ioc_args(runner):
    with runner.isolated_filesystem() as temp_dir:
        ioc_file_path = os.path.join(temp_dir, "ioc_list.txt")
        with open(ioc_file_path, 'w') as deffile:
            deffile.write("127.0.0.1")
        with pytest.raises(Exception) as e_info:
            Surveyor("cbr").survey(ioc_file=ioc_file_path)
            assert "--iocfile requires --ioctype" in e_info


def test_invalid_ioc_file(runner):
    with pytest.raises(Exception) as e_info:
        Surveyor("cbr").survey(ioc_file="nonexistent.txt", ioc_type="md5")
        assert "Supplied --iocfile is not a file" in str(e_info)


def test_mutually_exclusive_days_mins():
    with pytest.raises(Exception) as e_info:
        Surveyor("cbr").survey(days=3, minutes=4)
        assert "--days and --minutes are mutually exclusive" in str(e_info)


def test_output_argument_full_path(runner, mocker):
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    with runner.isolated_filesystem() as temp_dir:
        full_output_path = os.path.join(temp_dir, "full_output.csv")
        Surveyor("cbr").survey(output=full_output_path)
        assert os.path.exists(full_output_path)


def test_output_argument_filename(mocker):
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    filename_only = 'filename_only.csv'
    full_output_path = os.path.join(os.getcwd(), filename_only)
    Surveyor("cbr").survey(output=filename_only)
    assert os.path.exists(full_output_path)


def test_mutually_exclusive_output_prefix(mocker, capsys):
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    Surveyor("cbr").survey(prefix='test_prefix', output='test_output.csv')
    assert os.path.exists(os.path.join(os.getcwd(), "test_output.csv"))


def test_no_file_output(mocker):
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    default_output = 'surveyor.csv'
    Surveyor("cbr").survey(no_file=False)
    assert not os.path.exists(default_output)


def test_base_query_filters_with_query(mocker):
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_process_search = mocker.patch('products.vmware_cb_response.CbResponse.process_search')
    Surveyor("cbr").survey(query="SELECT * FROM processes", days=5, hostname="workstation1", username="admin")
    mocked_process_search.assert_called_once_with(Tag('query'), {'days':5, 'hostname':'workstation1','username':'admin'}, 'SELECT * FROM processes')


def test_sigma_rule(runner, mocker):
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    with runner.isolated_filesystem() as temp_dir:
        sigma_file_path = os.path.join(temp_dir, "test_sigma_rule.yml")
        with open(sigma_file_path, 'w') as sigmafile:
            sigmafile.write("""title: Test sigma rule
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
    - ParentCommandLine""")
        Surveyor("cbr").survey(sigma_rule=sigma_file_path)
        mocked_nested_process_search.assert_called_once_with(Tag('Test sigma rule - 5fd18e43-749c-4bae-93b6-d46e1f27062e', 'Sigma Rule'), {"query":["process_name:curl.exe"]}, {})


def test_sigma_rule_with_base_query(runner, mocker):
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    filter_args = ['--days', '5', '--hostname', 'workstation1', '--username', 'admin']
    with runner.isolated_filesystem() as temp_dir:
        sigma_file_path = os.path.join(temp_dir, "test_sigma_rule.yml")
        with open(sigma_file_path, 'w') as sigmafile:
            sigmafile.write("""title: Test sigma rule
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
    - ParentCommandLine""")
        Surveyor("cbr").survey(sigma_rule=sigma_file_path, days=5, hostname="workstation1", username="admin")
        mocked_nested_process_search.assert_called_once_with(Tag('Test sigma rule - 5fd18e43-749c-4bae-93b6-d46e1f27062e', 'Sigma Rule'), {"query":["process_name:curl.exe"]}, {'username':'admin', 'hostname':'workstation1','days':5 })


def test_sigma_dir(runner, mocker):
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    with runner.isolated_filesystem() as temp_dir:
        sigma_file_path1 = os.path.join(temp_dir, "test_sigma_rule1.yml")
        with open(sigma_file_path1, 'w') as sigmafile:
            sigmafile.write("""title: Test sigma rule
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
    - ParentCommandLine""")
            
        sigma_file_path2 = os.path.join(temp_dir, "test_sigma_rule2.yml")
        with open(sigma_file_path2, 'w') as sigmafile:
            sigmafile.write("""title: Test sigma rule 2
id: 15ecb82d-b7c0-4e53-9bf3-deedb4c9908c
description: Test sigma rule 2
logsource:
    category: process_creation
detection:
    selection:
        - Image: 'powershell.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine""")
        Surveyor("cbr").survey(sigma_dir=temp_dir)
        expected_calls = [mocker.call(Tag('Test sigma rule - 5fd18e43-749c-4bae-93b6-d46e1f27062e', 'Sigma Rule'), {"query":["process_name:curl.exe"]}, {}),
                          mocker.call(Tag('Test sigma rule 2 - 15ecb82d-b7c0-4e53-9bf3-deedb4c9908c', 'Sigma Rule'), {"query":["process_name:powershell.exe"]}, {})]
        mocked_nested_process_search.assert_has_calls(expected_calls, any_order=True)


def test_sigma_dir_with_base_query(runner, mocker):
    mocker.patch('products.vmware_cb_response.CbResponse._authenticate')
    mocked_nested_process_search = mocker.patch('products.vmware_cb_response.CbResponse.nested_process_search')
    filter_args = ['--days', '5', '--hostname', 'workstation1', '--username', 'admin']
    with runner.isolated_filesystem() as temp_dir:
        sigma_file_path1 = os.path.join(temp_dir, "test_sigma_rule1.yml")
        with open(sigma_file_path1, 'w') as sigmafile:
            sigmafile.write("""title: Test sigma rule
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
    - ParentCommandLine""")
            
        sigma_file_path2 = os.path.join(temp_dir, "test_sigma_rule2.yml")
        with open(sigma_file_path2, 'w') as sigmafile:
            sigmafile.write("""title: Test sigma rule 2
id: 15ecb82d-b7c0-4e53-9bf3-deedb4c9908c
description: Test sigma rule 2
logsource:
    category: process_creation
detection:
    selection:
        - Image: 'powershell.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine""")
        Surveyor("cbr").survey(sigma_dir=temp_dir, days=5, hostname="workstation1", username="admin")
        expected_calls = [mocker.call(Tag('Test sigma rule - 5fd18e43-749c-4bae-93b6-d46e1f27062e', 'Sigma Rule'), {"query":["process_name:curl.exe"]}, {'username':'admin', 'hostname':'workstation1','days':5 }),
                          mocker.call(Tag('Test sigma rule 2 - 15ecb82d-b7c0-4e53-9bf3-deedb4c9908c', 'Sigma Rule'), {"query":["process_name:powershell.exe"]}, {'username':'admin', 'hostname':'workstation1','days':5 })]
        mocked_nested_process_search.assert_has_calls(expected_calls, any_order=True)