import configparser
import json
import os

import requests
from typing import Union,Optional
from common import Product, Tag, Result
from datetime import datetime, timezone

PARAMETER_MAPPING: dict[str, dict[str, Union[str, list[str]]]] = {
    'process_name': {'table':'DeviceProcessEvents','field':'FolderPath',
                     'projections':['DeviceName','AccountName','FolderPath','ProcessCommandLine']},
    'filemod': {'table':'DeviceFileEvents','field':'FolderPath', 
                'projections':['DeviceName', 'InitiatingProcessAccountName','InitiatingProcessFolderPath','InitiatingProcessCommandLine']},
    'ipaddr': {'table':'DeviceNetworkEvents','field':'RemoteIP', 
               'projections':['DeviceName', 'InitiatingProcessAccountName','InitiatingProcessFolderPath','InitiatingProcessCommandLine']},
    'ipport': {'table':'DeviceNetworkEvents','field':'RemotePort', 
               'projections':['DeviceName', 'InitiatingProcessAccountName','InitiatingProcessFolderPath','InitiatingProcessCommandLine']},
    'cmdline': {'table':'DeviceProcessEvents','field':'ProcessCommandLine', 
                'projections':['DeviceName','AccountName','FolderPath','ProcessCommandLine']},
    'digsig_publisher': {'table':'DeviceFileCertificateInfo','field':'Signer', 
                         'additional':'| join kind=inner DeviceProcessEvents on $left.SHA1 == $right.SHA1',
                         'projections':['DeviceName', 'AccountName','FolderPath','ProcessCommandLine']},
    'domain': {'table':'DeviceNetworkEvents','field':'RemoteUrl', 
               'projections':['DeviceName', 'InitiatingProcessAccountName','InitiatingProcessFolderPath','InitiatingProcessCommandLine']},
    'internal_name': {'table':'DeviceProcessEvents','field':'ProcessVersionInfoInternalFileName', 
                      'projections':['DeviceName','AccountName','FolderPath','ProcessCommandLine']},
    'md5': {'table':'DeviceProcessEvents','field':'MD5',
            'projections':['DeviceName','AccountName','FolderPath','ProcessCommandLine']},
    'sha1':{'table':'DeviceProcessEvents','field':'SHA1',
            'projections':['DeviceName','AccountName','FolderPath','ProcessCommandLine']},
    'sha256':{'table':'DeviceProcessEvents','field':'SHA256',
              'projections':['DeviceName','AccountName','FolderPath','ProcessCommandLine']},
    'modload':{'table': 'DeviceImageLoadEvents', 'field':'FolderPath',
               'projections':['DeviceName', 'InitiatingProcessAccountName', 'InitiatingProcessFolderPath', 'InitiatingProcessCommandLine']},
    'regmod':{'table':'DeviceRegistryEvents','field':'RegistryKey',
              'projections':['DeviceName', 'InitiatingProcessAccountName', 'InitiatingProcessFolderPath', 'InitiatingProcessCommandLine', 'RegistryValueName', 'RegistryValueData']}
}

class DefenderForEndpoints(Product):
    """
    Surveyor implementation for product "Microsoft Defender For Endpoint"
    """
    profile: str = 'default'
    product: str = 'dfe'
    creds_file: str  # path to credential configuration file
    _token: str  # AAD access token
    _limit: int = -1
    _tenantId: Optional[str] = None
    _appId: Optional[str] = None
    _appSecret: Optional[str] = None
    _standardized: bool = True
    
    def __init__(self, **kwargs):

        self.profile = kwargs.get('profile', 'default')
        self.creds_file = kwargs.get('creds_file', '')
        self._token = kwargs.get('token', '')
        self._tenantId = kwargs.get('tenantId', '')
        self._appId = kwargs.get('appId', '')
        self._appSecret = kwargs.get('appSecret', '')
        self._standardized = False if kwargs.get("standardized")==False else True

        if 100000 >= int(kwargs.get('limit', -1)) > self._limit:
            self._limit = int(kwargs['limit'])

        super().__init__(self.product, **kwargs)

    def _authenticate(self) -> None:
        
        self.verify_creds

        if not self._token:
            self._token = self._get_aad_token(tenant_id=self._tenantId, app_id=self._appId, app_secret=self._appSecret) # type:ignore

    def _get_aad_token(self, tenant_id: str, app_id: str, app_secret: str) -> str:
        """
        Retrieve an authentication token from Azure Active Directory using app ID and secret.
        """
        self.log.debug(f'Acquiring AAD access token for tenant {tenant_id} and app {app_id}')

        body = {
            "resource": 'https://api.securitycenter.windows.com',
            "client_id": app_id,
            "client_secret": app_secret,
            "grant_type": "client_credentials"
        }

        url = f"https://login.windows.net/{tenant_id}/oauth2/token"

        response = requests.get(url, data=body)
        response.raise_for_status()

        return response.json()['access_token']

    def _post_advanced_query(self, data: dict, headers: dict, tag:Tag) -> list[Result]:
        results: set = set()

        try:
            url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
            response = requests.post(url, data=json.dumps(data).encode('utf-8'), headers=headers)

            if response.status_code == 200:
                for res in response.json()["Results"]:

                    result = Result(
                        hostname=res.get('DeviceName'), 
                        username=res.get('AccountName', res.get('InitiatingProcessAccountName')), 
                        path=res.get('FolderPath', res.get('InitiatingProcessFolderPath')), 
                        command_line=res.get('ProcessCommandLine',res.get('InitiatingProcessCommandLine')),
                        timestamp=res.get('Timestamp', datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')), # If timestamp is not present, return current time.
                        query=data.get('Query'),
                        label=tag.tag,
                        profile=self.profile,
                        product=self.product,
                        source=tag.source,
                        raw_data=(json.dumps(res)) # type:ignore
                        )
                    results.add(result)
            else:
                self.log.error(f"Received status code: {response.status_code} (message: {response.json()})")
        except KeyboardInterrupt:
            self.log.exception("Caught CTRL-C. Rerun surveyor")
        except Exception as e:
            self.log.exception(e)

        return list(results)

    def _get_default_header(self) -> dict[str, str]:
        return {
            "Authorization": 'Bearer ' + self._token,
            "Content-Type": 'application/json',
            "Accept": 'application/json'
        }

    def process_search(self, tag: Tag, base_query: dict, query: str) -> None:
        query = query.rstrip()
        
        query += f" {self.build_query(base_query)}" if base_query != {} else ''

        if self._limit > 0 and 'limit' not in query:
            query += f" | limit {str(self._limit)}"

        self.log.debug(f'Query: {query}')
        full_query = {'Query': query}

        results = self._post_advanced_query(data=full_query, headers=self._get_default_header(), tag=tag)

        self._add_results(list(results), tag)

    def nested_process_search(self, tag: Tag, criteria: dict, base_query: dict) -> None:
        query_base: str = self.build_query(base_query)

        try:
            for search_field, terms in criteria.items():
                if search_field == 'query':
                    if isinstance(terms, list):
                        for query_entry in terms:
                            query_entry += f" {query_base}" if query_base != '' else ''
                            self.process_search(tag, {}, query_entry)
                    else:
                        query_entry = terms
                        query_entry += f" {query_base}" if query_base != '' else ''

                        self.process_search(tag, {}, query_entry)
                else:
                    all_terms = ', '.join(f"'{term}'" for term in terms)
                    if search_field in PARAMETER_MAPPING:
                        query = f"| where {PARAMETER_MAPPING[search_field]['field']} has_any ({all_terms})"
                    else:
                        self.log.warning(f'Query filter {search_field} is not supported by product {self.product}')
                        continue
                
                    query = f"{PARAMETER_MAPPING[search_field]['table']} {query} "

                    query += f"{(PARAMETER_MAPPING[search_field]['additional'])} " if 'additional' in PARAMETER_MAPPING[search_field] else ''

                    query += f" {query_base} " if query_base != '' else ''

                    query += f"| project Timestamp, {', '.join(PARAMETER_MAPPING[search_field]['projections'])}"

                    self.process_search(tag, {}, query)
        except KeyboardInterrupt:
            self.log.exception("Caught CTRL-C. Returning what we have...")

    def build_query(self, filters: dict) -> str:
        query_base: list = list()
        if self._standardized == True:
            for key, value in filters.items():
                if key == 'days':
                    query_base.append(f'| where Timestamp > ago({value}d)')
                elif key == 'minutes':
                    query_base.append(f'| where Timestamp > ago({value}m)')
                elif key == 'hostname':
                    query_base.append(f'| where DeviceName contains "{value}"')
                elif key == 'username':
                    query_base.append(f'| where AccountName contains "{value}"')
                else:
                    self.log.warning(f'Query filter {key} is not supported by product {self.product}')

        return ' '.join(query_base)
    
    @property
    def verify_creds(self) -> None:
        if self._tenantId and self._appId and self._appSecret:
            self.log.info("Received tenantId, appId, and appSecret values needed to authenticate.")
        elif not os.path.isfile(self.creds_file):
            raise ValueError(f'Credential file {self.creds_file} does not exist')
        elif os.path.isfile(self.creds_file):
            config = configparser.ConfigParser()
            config.sections()
            config.read(self.creds_file)

            if self.profile not in config:
                raise ValueError(f'Profile {self.profile} is not present in credential file')

            section: Union[configparser.SectionProxy, dict] = config[self.profile]

            if 'token' in section:
                self._token = section['token']
            elif 'tenantId' not in section or 'appId' not in section or 'appSecret' not in section:
                raise ValueError(f'Credential file must contain a token or the fields tenantId, appId, and appSecret values')
            else:
                self._tenantId = section['tenantId']
                self._appId = section['appId']
                self._appSecret = section['appSecret']