import sys

# ensure Python version is compatible (Python v2 will always error out)
if sys.version_info.major == 3 and sys.version_info.minor < 10:
    raise Exception(f'Python 3.10+ is required to run Surveyor (current: {sys.version_info.major}.{sys.version_info.minor})')

import json
import logging
import os
from typing import Optional, Union, List
from datetime import datetime, timezone

from load import get_product_instance
from common import Tag, Result, sigma_translation

class Surveyor():
    product_args: dict = dict()
    log: logging.Logger = None
    results: list = list()
    supported_products: tuple = ('cbr', 'cbc', 'dfe', 'cortex', 's1')
    log_format = '[%(asctime)s] [%(levelname)-8s] [%(name)-36s] [%(filename)-20s:%(lineno)-4s] %(message)s'

    def __init__(self, product: str=None,
                 creds_file: Optional[str] = None,
                 profile: Optional[str] = 'default',
                 url: Optional[str] = None,
                 token: Optional[str] = None,
                 cbr_sensor_group: Optional[str]=None,
                 cbc_device_group: Optional[str] = None,
                 cbc_device_policy: Optional[str] = None,
                 cbc_org_key: Optional[str] = None,
                 cortex_tenant_ids: Optional[List[int]] = None,
                 cortex_api_key_id: Optional[int] = None,
                 cortex_auth_type: Optional[str] = None,
                 dfe_tenantId: Optional[str] = None,
                 dfe_appId: Optional[str] = None,
                 dfe_appSecret: Optional[str] = None,
                 s1_site_ids: Optional[List[str]] = None,
                 s1_account_ids: Optional[List[str]] = None,
                 s1_account_names: Optional[List[str]] = None,
                 **kwargs) -> dict:
        
        self.product_args.clear()
        self.results.clear()

        if not product:
            print(f"No product selected, in order to use surveyor please specify a product such as: {self.supported_products}")
        else:
            product = product.lower()

        args = {
            "product": product,
            "profile": profile
            }
        
        # Check if creds file exists for Cortex, S1, and DFE
        if product in ['cortex', 'dfe', 's1']:
            if creds_file:
                if os.path.exists(creds_file) and os.path.isfile(creds_file):
                    args['creds_file'] = creds_file
                else:
                    raise Exception(f"The creds_file doesn't exist at {creds_file} or is not a file. Please try again.")
                
        match product:
            case 'cbr':
                if cbr_sensor_group:
                    args['sensor_group'] = list(cbr_sensor_group)
                if token:
                    args['token'] = token
                if url:
                    args['url'] = url
                # Credentials file is not required for CbR, given that the SDK attempts to load from disk by default.\
                # If no credentials can be found or are not passed in as arguments, an exception will be raised
            case'cbc':
                if cbc_device_group:
                    args['device_group'] = list(cbc_device_group)
                if cbc_device_policy:
                    args['device_policy'] = list(cbc_device_policy)
                if token:
                    args['token'] = token
                if url:
                    args['url'] = url
                if cbc_org_key:
                    args['org_key'] = cbc_org_key
                    # Credentials file is not required for CbC, given that the SDK attempts to load from disk by default.\
                    #  If no credentials can be found or are not passed in as arguments, an exception will be raised
            case 'dfe':
                if token:
                    args['token'] = token
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
                if token:
                    args['api_key'] = token
                if cortex_api_key_id:
                    args['api_key_id'] = str(cortex_api_key_id)
                if url:
                    args['url'] = url
                if cortex_auth_type and isinstance(cortex_auth_type, str):
                    if cortex_auth_type.lower() in ['standard', 'advanced']:
                        args['auth_type'] = cortex_auth_type
                    else:
                        raise ValueError("Invalid auth_type specified for Cortex, please provide either 'standard' or 'advanced'")
                if not any([args.get('creds_file'), (args.get('token') and args.get('url') and args.get('api_key_id'))]):
                    raise Exception("Cortex requires either a creds_file or token (api_key), api_key_id, and url to be specified")
            case 's1':
                if s1_site_ids:
                    args['site_ids'] = s1_site_ids
                if s1_account_ids:
                    args['account_ids'] = s1_account_ids
                if s1_account_names:
                    args['account_names'] = s1_account_names
                if token:
                    args['token'] = token
                if url:
                    args["url"] = url
                if not any([args.get('creds_file'), [args.get('token') and args.get("url")]]):
                    raise Exception("S1 requires either a creds_file or token & URL to be specified")
                elif not args.get('creds_file') and not any([args.get('site_ids'), args.get('account_ids'), args.get('account_names')]):
                    raise Exception("S1 requires either site_ids, account_ids, or account_names to be specified")
      
        self.product_args = args


    def survey(self,
               hostname: Optional[str] = None,
               days: Optional[int] = None,
               minutes: Optional[int] = None,
               username: Optional[str] = None,
               limit: Optional[int] = None,
               ioc_list: Optional[list] = None,
               ioc_type: Optional[str] = None,
               query: Optional[str] = None,
               definitions: Optional[dict] = None,
               sigma_rule: Optional[str] = None,
               s1_use_powerquery: bool = True,
               label: Optional[str] = None,
               log_dir: Optional[str] = "logs",
               standardized: bool = True, 
               save_to_json_file: bool = False,
               save_dir: Optional[str] = "results",
               **kwargs) -> list:
        
        '''
        Args:
            hostname: (str) - endpoint to search for. Default all.
            days: (int) - number of days to look back. \
                Default the respective product's default value.
            minutes: (int) - number of minutes look back. \
                Mutally exclusive of days. Default products days default value
            username: (str) - username to search for. Default all.
            limit: (str) -number of results to return. \
                Default to products default value.
            ioc_list: (list) - IoCs to search want to search for. Default None
            query: (str) - Query to search. Default None
            definition: (dict)- JSON `defintions` to search for.
            sigma_rule: (str[yaml]) - str of sigma rule. Default None.
            label: (str) - Used for definitions. sigma, and IoC searches. \
                Use to label the output of data for easier searching. Default None
            log_dir: (str) - Where to store logs on disk.
            standardized: (bool) - By default, when requesting days, minutes, username, or a hostname during a search, these arguments can be appended to a query which may cause the query to fail. To run a query with no alterations, set standardized to False. This is most useful for freeform queries, if using definition files, sigma rules, or IoC lists, this should not cause any adverse impacts
            s1_use_powerquery: (bool) - Specify if S1 should use PowerQuery by default instead of Deep Visibility. Default is True.
        Returns:
            list of results

        
        '''
        
        self.results.clear()
        
        if str(self.product_args.get('product')) not in self.supported_products:
            raise Exception(f"product argument is required. Be sure to init the Surveyor class with a supported product {self.supported_products}")
        else:
            product = self.product_args['product']
            del self.product_args['product'] # remove product key from product_args after setting product

        if ioc_list and ioc_type is None:
            raise Exception("iocfile requires ioctype")

        if days and minutes:
            raise Exception('days and minutes are mutually exclusive')

        # instantiate a logger
        self.log = logging.getLogger('surveyor')
        logging.debug(f'Product: {product}')

        # configure logging
        root = logging.getLogger()
        root.setLevel(logging.DEBUG)
        root.handlers = list()  # remove all default handlers

        # create logging directory if it does not exist
        os.makedirs(log_dir, exist_ok=True)

        # create logging file handler
        current_time = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
        log_file_name = current_time + f'.{product}.log'
        handler = logging.FileHandler(os.path.join(log_dir, log_file_name))
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter(self.log_format))
        root.addHandler(handler)

        if len(self.product_args) > 0 and isinstance(self.product_args, dict):
            kwargs = self.product_args

        if isinstance(limit, (str, int)):
            kwargs['limit'] = str(limit)

        kwargs["pq"] = s1_use_powerquery if isinstance(s1_use_powerquery, bool) else True
        
        kwargs["standardized"] = standardized if isinstance(standardized, bool) else True

        # instantiate a product class instance based on the product string
        try:
            product = get_product_instance(product, **kwargs)
        except ValueError as e:
            self.log.exception(e)
            raise Exception(str(e))

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

        try:
            if query:
                # if a query is specified run it directly
                self.log.info(f"Running Custom Query: {query}")
                label = query if not label else label
                product.process_search(Tag(label), base_query, query)

                for tag, results in product.get_results().items():
                    self._save_results(results, tag)

            # run search based on IOC list
            if ioc_list:
                ioc_list = [x.strip() for x in ioc_list]
                label = "IoC List" if not label else label
                product.nested_process_search(Tag(label), {ioc_type: ioc_list}, base_query)

                for tag, results in product.get_results().items():
                    self._save_results(results, tag)
                        
            # run search against definition files and write to csv
            if definitions and isinstance(definitions, dict):
                for program, criteria in definitions.items():
                    product.nested_process_search(Tag(program), criteria, base_query)

                    if product.has_results():
                        # write results as they become available
                        for tag, nested_results in product.get_results(final_call=False).items():
                            self._save_results(nested_results, tag)
                            
                        # ensure results are only written once
                        product.clear_results()

                # write any remaining results
                for tag, nested_results in product.get_results().items():
                    self._save_results(nested_results, tag)
                    
            # if there's sigma rule to be processed
            if sigma_rule:
                pq_check = True if s1_use_powerquery else False
                translated_rules = sigma_translation(product.product, [sigma_rule], pq_check)
                if len(translated_rules['queries']) != len(sigma_rules):
                    self.log.warning(f"Only {len(translated_rules['queries'])} out of {len(sigma_rules)} were able to be translated.")
                
                for rule in translated_rules['queries']:
                    label = f"{rule['title']} - {rule['id']}" if not label else label

                    product.nested_process_search(Tag(label), {'query': [rule['query']]}, base_query)

                    if product.has_results():
                        # write results as they become available
                        for tag, nested_results in product.get_results(final_call=False).items():
                            self._save_results(nested_results, tag)
                        
                        # ensure results are only written once
                        product.clear_results()

                # write any remaining results
                for tag, nested_results in product.get_results().items():
                    self._save_results(nested_results, tag)

            if self.results and save_to_json_file:
                os.makedirs(save_dir, exist_ok=True)
                output_file = os.path.join(save_dir, "_".join([current_time, f'{str(self.product_args.get("profile"))}.json']))
                
                with open(output_file, "w") as f:
                    json.dump(self.results, f)

                logging.info(f"Saved results to {output_file}")
                    
            return self.results
        
        except KeyboardInterrupt:
            self.log.error("Caught CTRL-C. Exiting...")
        except Exception as e:
            self.log.error(f'Caught {type(e).__name__} (see log for details): {e}')


    def _save_results(self, results: list[Result], tag: Tag) -> Union[None, list]:
        """
        Helper function for writing search results to list.
        """

        if isinstance(tag, tuple):
            tag = tag[0]

        self.log.info(f"-->{tag.tag}: {len(results)} results")
       
        results = [result.__dict__ for result in results]
        self.results.extend(results)