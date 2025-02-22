import sys

# ensure Python version is compatible (Python v2 will always error out)
if sys.version_info.major == 3 and sys.version_info.minor < 10:
    raise Exception(f'Python 3.10+ is required to run Surveyor (current: {sys.version_info.major}.{sys.version_info.minor})')

import json
import logging
import os
from typing import Optional, Union, List
from datetime import datetime, timezone

from common import Tag, Result, sigma_translation
from load import get_product_instance

class Surveyor():
    product_args: dict = dict()
    log: logging.Logger = None
    raw_data: bool = False
    results: list = list()
    supported_products: tuple = ('cbr', 'cbc', 'dfe', 'cortex', 's1')
    log_format = '[%(asctime)s] [%(levelname)-8s] [%(name)-36s] [%(filename)-20s:%(lineno)-4s] %(message)s'

    def __init__(self, product_str: str=None,
                 creds_file: Optional[str] = None,
                 profile: Optional[str] = 'default',
                 cbr_sensor_group: Optional[str]=None,
                 cbr_token: Optional[str] = None,
                 cbr_url: Optional[str] = None,
                 cbc_device_group: Optional[str] = None,
                 cbc_device_policy: Optional[str] = None,
                 cbc_token: Optional[str] = None,
                 cbc_url: Optional[str] = None,
                 cbc_org_key: Optional[str] = None,
                 cortex_tenant_ids: Optional[List[int]] = None,
                 cortex_api_key: Optional[str] = None,
                 cortex_api_key_id: Optional[str] = None,
                 cortex_api_url: Optional[str] = None,
                 cortex_auth_type: Optional[str] = None,
                 dfe_token: Optional[str] = None,
                 dfe_tenantId: Optional[str] = None,
                 dfe_appId: Optional[str] = None,
                 dfe_appSecret: Optional[str] = None,
                 s1_site_ids: Optional[List[str]] = None,
                 s1_account_ids: Optional[List[str]] = None,
                 s1_account_names: Optional[List[str]] = None,
                 s1_token: Optional[str] = None,
                 s1_use_powerquery: bool=True,
                 **kwargs) -> dict:
        
        self.product_args.clear()
        if not product_str:
            print(f"No product selected, in order to use surveyor please specify a product such as: {self.supported_products}")
        else:
            product_str = product_str.lower()

        args = {
            "product": product_str,
            "profile": profile
            }
        
        # Check if creds file exists for Cortex, S1, and DFE
        if product_str in ['cortex', 'dfe', 's1']:
            if creds_file:
                if os.path.exists(creds_file) and os.path.isfile(creds_file):
                    args['creds_file'] = creds_file
                else:
                    raise Exception(f"The creds_file doesn't exist at {creds_file} or is not a file. Please try again.")
                
        match product_str:
            case 'cbr':
                if cbr_sensor_group:
                    args['sensor_group'] = list(cbr_sensor_group)
                if cbr_token:
                    args['token'] = cbr_token
                if cbr_url:
                    args['url'] = cbr_url
                # Credentials file is not required for CBR, given that the SDK attempts to load from disk by default.\
                # If no credentials can be found or are not passed in as arguments, an exception will be raised
            case'cbc':
                if cbc_device_group:
                    args['device_group'] = list(cbc_device_group)
                if cbc_device_policy:
                    args['device_policy'] = list(cbc_device_policy)
                if cbc_token:
                    args['token'] = cbc_token
                if cbc_url:
                    args['url'] = cbc_url
                if cbc_org_key:
                    args['org_key'] = cbc_org_key
                    # Credentials file is not required for CBC, given that the SDK attempts to load from disk by default.\
                    #  If no credentials can be found or are not passed in as arguments, an exception will be raised
            case 'dfe':
                if dfe_token:
                    args['token'] = dfe_token
                if dfe_tenantId:
                    args['tenantId'] = dfe_tenantId
                if dfe_appId:
                    args['appId'] = dfe_appId
                if dfe_appSecret:
                    args['appSecret'] = dfe_appSecret
                if not any([args.get('creds_file'), args.get('token'), (args.get('tenantId') and args.get('appId') and args.get('appSecret'))]):
                    raise Exception("DFE requires either a creds_file, or token, or tenantId, appId, and appSecret to be specified")
            case 'cortex':
                if cortex_tenant_ids:
                    args['tenant_ids'] = list(cortex_tenant_ids)
                if cortex_api_key:
                    args['api_key'] = cortex_api_key
                if cortex_api_key_id:
                    args['api_key_id'] = cortex_api_key_id
                if cortex_api_url:
                    args['url'] = cortex_api_url
                if cortex_auth_type and isinstance(cortex_auth_type, str):
                    if cortex_auth_type.lower() in ['standard', 'advanced']:
                        args['auth_type'] = cortex_auth_type
                    else:
                        raise ValueError("Invalid auth_type specified for Cortex, please provide either 'standard' or 'advanced'")
                if not any([args.get('creds_file'), (args.get('api_key') and args.get('url') and args.get('api_key_id'))]):
                    raise Exception("Cortex requires either a creds_file or api_key, api_key_id, and url to be specified")
            case 's1':
                if s1_site_ids:
                    args['site_ids'] = s1_site_ids
                if s1_account_ids:
                    args['account_ids'] = s1_account_ids
                if s1_account_names:
                    args['account_names'] = s1_account_names
                if not s1_use_powerquery:
                    args['pq'] = False
                if s1_token:
                    args['token'] = s1_token
                if not any([args.get('creds_file'), args.get('token')]):
                    raise Exception("S1 requires either a creds_file or token to be specified")
                elif not args.get('creds_file') and not any([args.get('site_ids'), args.get('account_ids'), args.get('account_names')]):
                    raise Exception("S1 requires either site_ids, account_ids, or account_names to be specified")
      
        self.product_args = args


    def survey(self,
               hostname: Optional[str] = None,
               days: Optional[int] = None,
               minutes: Optional[int] = None,
               username: Optional[str] = None,
               limit: Optional[int] = None,
               ioc_file: Optional[str] = None,
               ioc_type: Optional[str] = None,
               query: Optional[str] = None,
               def_dir: Optional[str] = None,
               def_file: Optional[str] = None,
               sigma_rule: Optional[str] = None,
               sigma_dir: Optional[str] = None,
               log_dir: Optional[str] = "logs",
               raw_data: bool = False,
               **kwargs) -> None:
        
        self.raw_data = raw_data if isinstance(raw_data, bool) else False
        
        if self.product_args.get('product') is None:
            raise Exception("product argument is required. Be sure to use setup_product_args() to set up the product arguments")
        else:
            product_str = self.product_args['product']
            del self.product_args['product'] # remove product key from product_args after setting product_str

        if product_str not in self.supported_products:
            raise Exception(f"Invalid product: {product_str}.\
                            Must be one of: {" ".join(self.supported_products)}")

        if ioc_file and ioc_type is None:
            raise Exception("iocfile requires ioctype")

        if ioc_file and not os.path.isfile(ioc_file):
            raise Exception('Supplied iocfile is not a file')

        if days and minutes:
            raise Exception('days and minutes are mutually exclusive')

        if sigma_rule and not os.path.isfile(sigma_rule):
            raise Exception('Supplied sigmarule is not a file')

        if sigma_dir and not os.path.isdir(sigma_dir):
            raise Exception('Supplied sigmadir is not a directory')

        # instantiate a logger
        self.log = logging.getLogger('surveyor')
        logging.debug(f'Product: {product_str}')

        # configure logging
        root = logging.getLogger()
        root.setLevel(logging.DEBUG)
        root.handlers = list()  # remove all default handlers

        # create logging directory if it does not exist
        os.makedirs(log_dir, exist_ok=True)

        # create logging file handler
        log_file_name = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S') + f'.{product_str}.log'
        handler = logging.FileHandler(os.path.join(log_dir, log_file_name))
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter(self.log_format))
        root.addHandler(handler)

        if len(self.product_args) > 0 and isinstance(self.product_args, dict):
            kwargs = self.product_args

        if limit:
            kwargs['limit'] = str(limit)

        # instantiate a product class instance based on the product string
        try:
            product = get_product_instance(product_str, **kwargs)
        except ValueError as e:
            self.log.exception(e)
            raise Exception(str(e))

        # placeholder for definition files if defdir or deffile is selected
        definition_files = list()

        # base_query stores the filters applied to the product query
        # initial query is retrieved from product instance
        base_query = product.base_query()

        # placeholder for sigma rules if sigmarule or sigmadir is selected
        sigma_rules = list()
        
        base_query.update(dict(
            username=username, hostname=hostname, days=days, minutes=minutes)
            )
        
        # Delete all empty items in base_query
        base_query = {k:v for k,v in base_query.items() if v}

        collected_results = []

        try:
            if query:
                # if a query is specified run it directly
                self.log.info(f"Running Custom Query: {query}")
                product.process_search(Tag('query'), base_query, query)

                for tag, results in product.get_results().items():
                    self._save_results(results, query, "query", tag)

            # test if deffile exists
            # deffile can be resolved from 'definitions' folder without needing to specify path or extension
            if def_file:
                if not os.path.exists(def_file):
                    repo_deffile: str = os.path.join(os.path.dirname(__file__), 'definitions', def_file)
                    if not repo_deffile.endswith('.json'):
                        repo_deffile = repo_deffile + '.json'

                    if os.path.isfile(repo_deffile):
                        self.log.debug(f'Using repo definition file {repo_deffile}')
                        def_file = repo_deffile
                    else:
                        raise Exception("The deffile doesn't exist. Please try again.")
                definition_files.append(def_file)

            # add sigma_rule to list
            if sigma_rule:
                sigma_rules.append(sigma_rule)

            # if defdir add all files to list
            if def_dir:
                if not os.path.exists(def_dir):
                    raise Exception("The defdir doesn't exist. Please try again.")
                else:
                    for root_dir, dirs, files in os.walk(def_dir):
                        for filename in files:
                            if os.path.splitext(filename)[1] == '.json':
                                definition_files.append(os.path.join(root_dir, filename))

            # if sigma_dir, add all files to sigma_rules list
            if sigma_dir:
                for root_dir, dirs, files in os.walk(sigma_dir):
                    for filename in files:
                        if os.path.splitext(filename)[1] == '.yml':
                            sigma_rules.append(os.path.join(root_dir, filename))

            # run search based on IOC file
            if ioc_file:
                with open(ioc_file) as f:
                    basename = os.path.basename(ioc_file)
                    data = f.readlines()
                    self.log.info(f"Processing IOC file: {ioc_file}")

                    ioc_list = [x.strip() for x in data]

                    product.nested_process_search(Tag(f"IOC - {ioc_file}", data=basename), {ioc_type: ioc_list}, base_query)

                    for tag, results in product.get_results().items():
                        self._save_results(results, ioc_file, 'ioc', tag)
                        
            # run search against definition files and write to csv
            if def_file is not None or def_dir is not None:
                for definitions in definition_files:
                    basename = os.path.basename(definitions)
                    source = os.path.splitext(basename)[0]

                    with open(definitions, 'r') as file:
                        programs = json.load(file)
                        for program, criteria in programs.items():
                            product.nested_process_search(Tag(program, data=source), criteria, base_query)

                            if product.has_results():
                                # write results as they become available
                                for tag, nested_results in product.get_results(final_call=False).items():
                                    self._save_results(nested_results, program, str(tag.data), tag)
                                    
                                # ensure results are only written once
                                product.clear_results()

                # write any remaining results
                for tag, nested_results in product.get_results().items():
                    self._save_results(nested_results, tag.tag, str(tag.data), tag)
                    
            # if there's sigma rules to be processed
            if len(sigma_rules) > 0:
                pq_check = True if 'pq' in self.product_args and self.product_args['pq'] else False
                translated_rules = sigma_translation(product_str, sigma_rules, pq_check)
                if len(translated_rules['queries']) != len(sigma_rules):
                    self.log.warning(f"Only {len(translated_rules['queries'])} out of {len(sigma_rules)} were able to be translated.")
                for rule in translated_rules['queries']:
                    program = f"{rule['title']} - {rule['id']}"
                    source = 'Sigma Rule'

                    product.nested_process_search(Tag(program, data=source), {'query': [rule['query']]}, base_query)

                    if product.has_results():
                        # write results as they become available
                        for tag, nested_results in product.get_results(final_call=False).items():
                            self._save_results(nested_results, program, str(tag.data), tag)
                        
                        # ensure results are only written once
                        product.clear_results()

                # write any remaining results
                for tag, nested_results in product.get_results().items():
                    self._save_results(nested_results, tag.tag, str(tag.data), tag)
                    
            return collected_results
        
        except KeyboardInterrupt:
            self.log.error("Caught CTRL-C. Exiting...")
        except Exception as e:
            self.log.error(f'Caught {type(e).__name__} (see log for details): {e}')


    def _save_results(self, results: list[Result], program: str, source: str,
                   tag: Tag) -> Union[None, list]:
        """
        Helper function for writing search results to list.
        """


        if isinstance(tag, tuple):
            tag = tag[0]

        if len(results) > 0:
            self.log.info(f"\033[92m-->{tag.tag}: {len(results)} results \033[0m")
        else:
            self.log.info(f"-->{tag.tag}: {len(results)} results")

        for result in results:
            row = result.__dict__ if not self.raw_data else json.loads(result.raw_data)
            row.update(dict(program=program, source=source))
            self.results.append(row)