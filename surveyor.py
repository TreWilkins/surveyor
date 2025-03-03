import sys

# ensure Python version is compatible (Python v2 will always error out)
if sys.version_info.major == 3 and sys.version_info.minor < 10:
    raise Exception(f'Python 3.10+ is required to run Surveyor (current: {sys.version_info.major}.{sys.version_info.minor})')

import os
import csv
import json
import logging
import requests
import yaml # type: ignore
from tqdm import tqdm # type: ignore
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Union, List, Callable, Tuple

from common import Tag, Result, sigma_translation
from load import get_product_instance, get_products

# Application version
current_version = "2.5.0"

@dataclass
class CLIExecutionOptions:
    profile: str
    hostname: Optional[str]
    days: Optional[int]
    minutes: Optional[int]
    username: Optional[str]
    limit: Optional[int]
    ioc_list: Optional[str]
    ioc_type: Optional[str]
    query: Optional[str]
    output: Optional[str]
    def_dir: Optional[str]
    definition: Optional[str]
    sigma_rule: Optional[str]
    sigma_dir: Optional[str]
    log_dir: str
    s1_use_powerquery: bool
    save_to_csv_file: bool
    save_to_json_file:bool
    use_tqdm: bool


class Surveyor():
    product_args: dict = None # type:ignore
    log: logging.Logger
    supported_products: tuple = ('cbr', 'cbc', 'dfe', 'cortex', 's1')
    log_format = '[%(asctime)s] [%(levelname)-8s] [%(name)-36s] [%(filename)-20s:%(lineno)-4s] %(message)s'

    def __init__(self,
                 product: Optional[str] = None,
                 profile: Optional[str] = None,
                 creds_file: Optional[str] = None,
                 url: Optional[str] = None,
                 token: Optional[str] = None,
                 cbr_sensor_group: Union[Tuple[str], List[str], str, None] = None,
                 cbc_device_group: Union[Tuple[str], List[str], str, None] = None,
                 cbc_device_policy: Union[Tuple[str], List[str], str, None] = None,
                 cbc_org_key: Optional[str] = None,
                 cortex_tenant_ids: Union[Tuple[str], List[str], str, None] = None,
                 cortex_api_key_id: Optional[int] = None,
                 cortex_auth_type: Optional[str] = None,
                 dfe_tenantId: Optional[str] = None,
                 dfe_appId: Optional[str] = None,
                 dfe_appSecret: Optional[str] = None,
                 s1_site_ids: Union[Tuple[str], List[str], str, None] = None,
                 s1_account_ids: Union[Tuple[str], List[str], str, None] = None,
                 s1_account_names: Union[Tuple[str], List[str], str, None] = None,
                 **kwargs) -> None:

        self.product_args = {}

        if not product:
            print(f"No product selected, in order to use surveyor please specify a product such as: {self.supported_products}")
        else:
            product = product.lower()

        args = dict(product=product, profile=profile)
        
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
                    args['sensor_group'] = cbr_sensor_group if isinstance(cbr_sensor_group, list) else [cbr_sensor_group] # type:ignore
                if token:
                    args['token'] = token
                if url:
                    args['url'] = url
                # Credentials file is not required for CbR, given that the SDK attempts to load from disk by default.\
                # If no credentials can be found or are not passed in as arguments, an exception will be raised
            case'cbc':
                if cbc_device_group:
                    args['device_group'] = cbc_device_group if (isinstance(cbc_device_group, list) or isinstance(cbc_device_group, tuple)) else [cbc_device_group] # type:ignore
                if cbc_device_policy:
                    args['device_policy'] = cbc_device_policy if (isinstance(cbc_device_policy, list) or isinstance(cbc_device_policy, tuple)) else [cbc_device_policy] # type:ignore
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
                    args['tenant_ids'] = cortex_tenant_ids if (isinstance(cortex_tenant_ids, list) or isinstance(cortex_tenant_ids, tuple)) else [cortex_tenant_ids] # type:ignore
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
                if not any([args.get('creds_file'), (args.get('api_key') and args.get('url') and args.get('api_key_id'))]):
                    raise Exception("Cortex requires either a creds_file or token (api_key), api_key_id, and url to be specified")
            case 's1':
                if s1_site_ids:
                    args['site_ids'] = s1_site_ids if (isinstance(s1_site_ids, list) or isinstance(s1_site_ids, tuple)) else [s1_site_ids] # type:ignore
                if s1_account_ids:
                    args['account_ids'] = s1_account_ids if (isinstance(s1_account_ids, list) or isinstance(s1_account_ids, tuple)) else [s1_account_ids] # type:ignore
                if s1_account_names:
                    args['account_names'] = s1_account_names if (isinstance(s1_account_names, list) or isinstance(s1_account_names, tuple)) else [s1_account_names] # type:ignore
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
               ioc_list: Union[list, str, None] = None,
               ioc_type: Optional[str] = None,
               query: Optional[str] = None,
               definition: Union[dict, str, None] = None,
               def_dir: Optional[str] = None,
               output: Optional[str] = None,
               hunt_query_file: Optional[str] = None,
               sigma_rule: Optional[str] = None,
               sigma_dir: Optional[str] = None,
               s1_use_powerquery: bool = True,
               label: Optional[str] = None,
               log_dir: str = "logs",
               save_to_json_file: bool = False,
               save_to_csv_file: bool = False,
               standardized: bool = True, 
               save_dir: str = "results",
               use_tqdm: bool = False,
               **kwargs) -> list:
        
        '''
        Args:
            profile: (str) - The credentials profile to use.
            hostname: (str) - endpoint to search for. Default all.
            days: (int) - number of days to look back. \
                Default the respective product's default value.
            minutes: (int) - number of minutes look back. \
                Mutally exclusive of days. Default products days default value
            username: (str) - username to search for. Default all.
            limit: (str) -number of results to return. \
                Default to products default value.
            ioc_list: (list, str) - IoCs to search want to search for. Default None
            ioc_type: (str) - The type of IoCs provided (ipaddr, sha256, md5, domain).
            query: (str) - Query to search. If sourcing from file, provide path to file.
            definition: (dict, str) - JSON `definitions` to search for. If sourcing from file, provide path unless the file exists in the projects `definitions` directory.
            defdir: (str) - Directory containing multiple definition files.
            hunt_query_file: (str) - Provide path to hunt query file (YAML). Will auto-resolve files existing in the `hunt_queries` directory of the projects folder. 
            sigma_rule: (str[yaml], str) - str of sigma rule, or path to file.
            sigmadir: (str) - Directory containing multiple sigma rule files.
            label: (str) - Used for definitions. sigma, and IoC searches. \
                Use to label the output of data for easier searching. Default None
            log_dir: (str) - Where to store logs on disk.
            save_to_json_file: bool - Save results to JSON file. Default False.
            save_to_csv_file: bool - Save results to CSV file. Default False.
            save_dir: str - Directory where results will be saved. Defauly `results` of the project folder.
            standardized: (bool) - By default, when requesting days, minutes, username, or a hostname during a search, these arguments can be appended to a query which may cause the query to fail. To run a query with no alterations, set standardized to False. This is most useful for freeform queries, if using definition files, sigma rules, or IoC lists, this should not cause any adverse impacts
            s1_use_powerquery: (bool) - Specify if S1 should use PowerQuery by default instead of Deep Visibility. Default is True.
            use_tqdm: (bool) - Use tqdm for progress bar. Default False.
        Returns:
            list of results
        '''
        
        if save_to_csv_file or save_to_json_file:
            os.makedirs(name = save_dir, exist_ok=True) 

        collected_results: list = list()
        
        if str(self.product_args.get('product')) not in self.supported_products:
            raise Exception(f"product argument is required. Be sure to init the Surveyor class with a supported product {self.supported_products}")
        else:
            product_str = self.product_args['product']
            del self.product_args['product'] # remove product key from product_args after setting product

        if ioc_list and ioc_type is None:
            raise Exception("iocfile requires ioctype")

        if days and minutes:
            raise Exception('days and minutes are mutually exclusive')

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
        current_time = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
        log_file_name = current_time + f'.{product_str}_{os.urandom(6).hex()}_{self.product_args.get("profile")}.log'
        handler = logging.FileHandler(os.path.join(log_dir, log_file_name))
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter(self.log_format))
        root.addHandler(handler)

        writer = None
        if save_to_csv_file:
            output_file = os.path.join(save_dir, "_".join([current_time, f'{str(self.product_args.get("profile"))}.csv' if not output else output]))
            output_file = open(output_file, 'w', newline='', encoding='utf-8') # type:ignore
            writer = csv.writer(output_file) # type:ignore
            writer.writerow(list(Result.__annotations__.keys()))

        if len(self.product_args) > 0 and isinstance(self.product_args, dict):
            kwargs = self.product_args
        
        if hunt_query_file:
            # If running a hunt query, do not append anything additional to a query that may cause errors.
            standardized = False

        if isinstance(limit, (str, int)):
            kwargs['limit'] = str(limit)

        kwargs["pq"] = s1_use_powerquery if isinstance(s1_use_powerquery, bool) else True
        
        kwargs["standardized"] = standardized if isinstance(standardized, bool) else True
        
        # instantiate a product class instance based on the product string
        try:
            product = get_product_instance(product_str, **kwargs)
        except ValueError as e:
            self.log.exception(e)
            raise Exception(str(e))

        # base_query stores the filters applied to the product query
        # initial query is retrieved from product instance
        base_query = product.base_query()

        # placeholder for sigma rules if sigmarule or sigmadir is selected
        sigma_rules = list() if not sigma_rule else [sigma_rule]
        definitions = list() if not definition else [definition]

        # if defdir add all files to list
        if def_dir:
            if not os.path.exists(def_dir):
                self.log.error("The defdir doesn't exist. Please try again.")
            else:
                for root_dir, dirs, files in os.walk(def_dir):
                    for filename in files:
                        if os.path.splitext(filename)[1] == '.json':
                            definitions.append(os.path.join(root_dir, filename))

        # if sigma_dir, add all files to sigma_rules list
        if sigma_dir:
            for root_dir, dirs, files in os.walk(sigma_dir):
                for filename in files:
                    if os.path.splitext(filename)[1] == '.yml':
                        sigma_rules.append(os.path.join(root_dir, filename))
        
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
                    collected_results.extend(self._save_results(results, tag, writer, use_tqdm))

            # run search based on IoC list
            elif ioc_list:
                source_file = os.path.basename(ioc_list) if isinstance(ioc_list, str) and os.path.isfile(ioc_list) else None
                if source_file:
                    with open(source_file) as iocs:
                        ioc_list = iocs.readlines()

                ioc_list = [x.strip() for x in ioc_list]
                label = f"IoC list{f' - {label}' if label else ''}"
                product.nested_process_search(Tag(label, source_file), {ioc_type: ioc_list}, base_query)

                for tag, results in product.get_results().items():
                    collected_results.extend(self._save_results(results, tag, writer, use_tqdm))
                        
            # run search against definition
            elif definitions:
                for definition in definitions:
                    source_file = None
                    if isinstance(definition, str):
                        if not os.path.exists(definition):
                            repo_deffile: str = os.path.join(os.path.dirname(__file__), 'definitions', definition)
                            if not repo_deffile.endswith('.json'):
                                repo_deffile = repo_deffile + '.json'

                            if os.path.isfile(repo_deffile):
                                self.log.debug(f'Using repo definition file {repo_deffile}')
                                definition = repo_deffile
                            else:
                                self.log.error(f"The definition file {repo_deffile} doesn't exist. Please try again.")
                        
                        source_file = os.path.basename(definition)
                        with open(definition) as f:
                            definition = f.read()
                        definition = json.loads(definition)

                    elif not isinstance(definition, dict):
                        raise TypeError(f"Definition file in unsupported format {type(definition)}, expected format --> dict")
                    
                    for program, criteria in definition.items(): # type:ignore
                        product.nested_process_search(Tag(program, source_file), criteria, base_query)

                        if product.has_results():
                            # write results as they become available
                            for tag, nested_results in product.get_results(final_call=False).items():
                                collected_results.extend(self._save_results(nested_results, tag, writer, use_tqdm))
                                
                            # ensure results are only written once
                            product.clear_results()

                    # write any remaining results
                    for tag, nested_results in product.get_results().items():
                        collected_results.extend(self._save_results(nested_results, tag, writer, use_tqdm))
                    
            # if there's sigma rules to be processed
            elif sigma_rules:
                for sigma_rule in sigma_rules:
                    source_file = os.path.basename(sigma_rule) if isinstance(sigma_rule, str) and os.path.isfile(sigma_rule) else None
                    pq_check = True if s1_use_powerquery else False
                    translated_rules = sigma_translation(product.product, [sigma_rule], pq_check)  # type:ignore
                    if len(translated_rules['queries']) != len(sigma_rules):
                        self.log.warning(f"Only {len(translated_rules['queries'])} out of {len(sigma_rules)} were able to be translated.")
                    
                    for rule in translated_rules['queries']:
                        label = f"{rule['title']} - {rule['id']}" if not label else label

                        product.nested_process_search(Tag(label, source_file), {'query': [rule['query']]}, base_query)

                        if product.has_results():
                            # write results as they become available
                            for tag, nested_results in product.get_results(final_call=False).items():
                                collected_results.extend(self._save_results(nested_results, tag, writer, use_tqdm))
                            
                            # ensure results are only written once
                            product.clear_results()

                    # write any remaining results
                    for tag, nested_results in product.get_results().items():
                        collected_results.extend(self._save_results(nested_results, tag, writer, use_tqdm))

            elif hunt_query_file:
                queries = []
                if not os.path.exists(hunt_query_file):
                    repo_huntfile: str = os.path.join(os.path.dirname(__file__), 'hunt_queries', hunt_query_file)
                    if not repo_huntfile.endswith('.yaml'):
                        repo_huntfile = repo_huntfile + '.yaml'

                    if os.path.isfile(repo_huntfile):
                        self.log.debug(f'Using repo hunt query file {repo_huntfile}')
                        hunt_query_file = repo_huntfile
                    else:
                        self.log.error(f"The hunt query file {hunt_query_file} doesn't exist. Please try again.")

                with open(hunt_query_file) as f:
                    data = yaml.safe_load(f)
                    if not set(["title", "description", "platforms"]).issubset(data.keys()):
                        self.log.error("The YAML file must contain the following keys: title, description, and platforms.")
                    for i in data["platforms"]:
                        if i.get(product_str) and isinstance(i[product_str], list):
                            queries.extend(i[product_str])
                        elif list(i.keys())[0].startswith(product_str) and product_str == "s1":
                            queries.append(i)

                    if not queries:
                        self.log.error(f"No queries found for {product_str}. Skipping.")

                    label = data.get("title") if not label else label
                    for query in queries:
                        product.process_search(Tag(label, hunt_query_file), base_query, query) # type:ignore

                        for tag, results in product.get_results().items():
                            collected_results.extend(self._save_results(results, tag, writer, use_tqdm))
            if use_tqdm:
                tqdm.write(f"\n\033[95mLog: {log_file_name}\033[0m")

            if collected_results:
                logging.info(f"Total results: {len(collected_results)}")
                if save_to_json_file:
                    os.makedirs(save_dir, exist_ok=True)
                    output_file = os.path.join(save_dir, "_".join([current_time, f'{str(self.product_args.get("profile"))}.json' if not output else output]))
                    
                    with open(output_file, "w") as f:
                        json.dump(collected_results, f)

                    logging.info(f"Saved results to {output_file}")
                
                if writer:
                    output_file.close() # type:ignore
                    logging.info(f"Saved results to {output_file.name}") # type:ignore
                    if use_tqdm:
                        tqdm.write(f"\033[95mResults saved: {output_file.name}\033[0m") # type:ignore
        
        except KeyboardInterrupt:
            self.log.error("Caught CTRL-C. Exiting...")
        except Exception as e:
            self.log.error(f'Caught {type(e).__name__} (see log for details): {e}')

        return collected_results

    def _save_results(self, results: list[Result], tag: Tag, writer: Union[csv.writer, None], use_tqdm: bool=False) -> list: # type:ignore
        """
        Helper function for writing search results to list and/or CSV.
        """

        if isinstance(tag, tuple):
            tag = tag[0]
        
        if use_tqdm:
            if len(results) > 0:
                tqdm.write(f"\033[92m-->{tag.tag}: {len(results)} results \033[0m")
            else:
                tqdm.write(f"-->{tag.tag}: {len(results)} results")
        else:
            self.log.info(f"-->{tag.tag}: {len(results)} results")

        for idx, result in enumerate(results):
            result = result.__dict__ # type:ignore
            raw_data = result.get("raw_data") # type:ignore
            if isinstance(raw_data, str):
                try:
                    raw_data = {k:v for k,v in json.loads(raw_data).items()}
                    result["raw_data"] = raw_data if not writer else str(raw_data) # type:ignore
                except Exception as e:
                    self.log.error("Error converting all values of raw_data into string")
                
            results[idx] = result
            if writer: 
                writer.writerow(list(result.values()))
        
        return results if isinstance(results, list) else []


def local_lambda(event: dict = {}, product_args: dict = {}, survey: dict = {}) -> Union[requests.Response, None]:

    if not event and not all([product_args,survey]):
        raise ValueError("To run Surveyor an event dictionary containing an\
            initialization and survey structure must be present. You can\
            supply an event dict with both nested structured, or supply\
            them individually by passing both the `product_args` and\
            `survey` arguments.")
    elif product_args and survey:
        event=dict(init=product_args, args=survey)
    elif not all([event.get("init"), event.get("args")]):
        raise ValueError("Necessary arguments not passed to use Surveyor. Please ensure credentials are provided, along with search criteira.")

    url = os.getenv("SURVEYOR_URL", "http://localhost:9000/2015-03-31/functions/function/invocations")
    try:
        r = requests.post(url=url, json=event)
        return r
    except (ConnectionRefusedError,Exception) as e:
        if not os.getenv("SURVEYOR_URL"):
            print(f"Ensure the SURVEYOR_URL environment variable is set to {url}. Error: {e}")
        else:
            print(f"Ensure the docker container is running at {url}. Error: {e}")
    
    return None


if __name__ == "__main__":
    import click
    # noinspection SpellCheckingInspection
    @click.group("surveyor", context_settings=dict(help_option_names=["-h", "--help", "-what-am-i-doing"]), invoke_without_command=True, chain=False)
    # filtering options
    @click.option("--profile", help="The credentials profile to use.", type=click.STRING)
    @click.option("--days", help="Number of days to search.", type=click.INT)
    @click.option("--minutes", help="Number of minutes to search.", type=click.INT)
    @click.option("--limit",help="""
                Number of results to return. Cortex XDR: Default: 1000, Max: Default
                Microsoft Defender for Endpoint: Default/Max: 100000
                SentinelOne (PowerQuery): Default/Max: 1000
                SentinelOne (Deep Visibility): Default/Max: 20000
                VMware Carbon Black EDR: Default/Max: None
                VMware Carbon Black Cloud Enterprise EDR: Default/Max: None
                
                Note: Exceeding the maximum limits will automatically set the limit to its maximum value, where applicable.
                """
                , type=click.INT)
    @click.option("--hostname", help="Target specific host by name.", type=click.STRING)
    @click.option("--username", help="Target specific username.")
    # different ways you can survey the EDR
    @click.option("--deffile", 'def_file', help="Definition file to process (must end in .json).", type=click.STRING)
    @click.option("--defdir", 'def_dir', help="Directory containing multiple definition files.", type=click.STRING)
    @click.option("--json", 'save_to_json_file', help="Use Deep Visibility for queries", is_flag=True, required=False)
    @click.option("--query", help="A single query to execute.")
    @click.option("--iocfile", 'ioc_file', help="IOC file to process. One IOC per line. REQUIRES --ioctype")
    @click.option("--ioctype", 'ioc_type', help="One of: ipaddr, domain, md5, sha256")
    @click.option("--sigmarule", 'sigma_rule', help="Sigma rule file to process (must be in YAML format).", type=click.STRING)
    @click.option("--sigmadir", 'sigma_dir', help='Directory containing multiple sigma rule files.', type=click.STRING)
    # optional output
    @click.option("--output", "--o", help="Specify the output file for the results. "
                                        "The default is create survey.csv in the current directory.")
    # version option
    @click.version_option(current_version)
    # logging options
    @click.option("--log-dir", 'log_dir', help="Specify the logging directory.", type=click.STRING, default='logs')
    @click.pass_context
    def cli(ctx, 
            profile: str,
            hostname: Optional[str],
            days: Optional[int],
            minutes: Optional[int],
            username: Optional[str],
            limit: Optional[int],
            ioc_file: Optional[str],
            ioc_type: Optional[str],
            query: Optional[str],
            output: Optional[str],
            def_dir: Optional[str],
            def_file: Optional[str],
            sigma_rule: Optional[str],
            sigma_dir: Optional[str],
            log_dir: str,
            save_to_json_file: bool
            ) -> None:

        ctx.ensure_object(dict)
        ctx.obj = CLIExecutionOptions(
            profile=profile, 
            hostname=hostname,
            days=days,
            minutes=minutes,
            username=username,
            limit=limit,
            ioc_list=ioc_file,
            ioc_type=ioc_type,
            query=query,
            output=output,
            def_dir=def_dir, 
            definition=def_file,
            sigma_rule=sigma_rule,
            sigma_dir=sigma_dir,
            log_dir=log_dir,
            s1_use_powerquery=True,
            save_to_csv_file=not save_to_json_file,
            save_to_json_file=save_to_json_file,
            use_tqdm=True
            )

        if ctx.invoked_subcommand is None:
            Surveyor('cbr').survey(**filtered_ctx_object(ctx.obj))

    def filtered_ctx_object(object):
        return {k:v for k,v in object.__dict__.items() if k != "profile"}
    
    # Cortex options
    @cli.command('cortex', help="Query Cortex XDR")
    @click.option("--creds", 'creds', help="Path to credential file", type=click.Path(exists=True), required=True)
    @click.pass_context
    def cortex(ctx, creds: Optional[str]) -> None:

        Surveyor('cortex', creds_file=creds, profile=ctx.obj.profile).survey(**filtered_ctx_object(ctx.obj))

    # S1 options
    @cli.command('s1', help="Query SentinelOne")
    @click.option("--site-id", help="ID of SentinelOne site to query", multiple=True, default=list())
    @click.option("--account-id", help="ID of SentinelOne account to query", multiple=True, default=list())
    @click.option("--account-name", help="Name of SentinelOne account to query", multiple=True, default=list())
    @click.option("--creds", 'creds', help="Path to credential file", type=click.Path(exists=True), required=True)
    @click.option("--dv", 'dv', help="Use Deep Visibility for queries", is_flag=True, required=False)
    @click.pass_context
    def s1(ctx, site_id: Optional[Tuple], account_id: Optional[Tuple], account_name: Optional[Tuple], creds: Optional[str],
        dv: bool) -> None:
        site_id = site_id
        account_id = account_id
        account_name = account_name
        ctx.obj["s1_use_powerquery"] = not dv
        
        Surveyor("s1", 
                 creds_file=creds, 
                 s1_account_ids=account_id, 
                 s1_account_names=account_name, 
                 s1_site_ids=site_id,
                 profile = ctx.obj.profile
                 ).survey(**filtered_ctx_object(ctx.obj))


    # CbC options
    @cli.command('cbc', help="Query VMware Cb Enterprise EDR")
    @click.option("--device-group", help="Name of device group to query", multiple=True, default=None)
    @click.option("--device-policy", help="Name of device policy to query", multiple=True, default=None)
    @click.pass_context
    def cbc(ctx, device_group: Optional[Tuple], device_policy: Optional[Tuple]) -> None:

        Surveyor('cbc',
                 cbc_device_group=device_group,
                 cbc_device_policy=device_policy,
                 profile = ctx.obj.profile
                 ).survey(**filtered_ctx_object(ctx.obj))


    # CbR Options
    @cli.command('cbr', help="Query VMware Cb Response")
    @click.option("--sensor-group", help="Name of sensor group to query", multiple=True, default=None)
    @click.pass_context
    def cbr(ctx, sensor_group: Optional[Tuple]) -> None:
        print(ctx.obj.profile)
        Surveyor(product="cbr", cbr_sensor_group=sensor_group, profile = ctx.obj.profile).survey(**filtered_ctx_object(ctx.obj))


    # DFE options
    @cli.command('dfe', help="Query Microsoft Defender for Endpoints")
    @click.option("--creds", 'creds', help="Path to credential file", type=click.Path(exists=True), required=True)
    @click.pass_context
    def dfe(ctx, creds: Optional[str]) -> None:
        Surveyor('dfe', creds_file=creds, profile = ctx.obj.profile).survey(**filtered_ctx_object(ctx.obj))

    def create_generic_product_command(name: str) -> Callable:
        @click.pass_context
        def command(ctx):
            Surveyor(name)

        command.__name__ = name
        return command


    # create click commands for all products that don't have a command function defined
    for product_name in get_products():
        dir_res = dir()
        if product_name not in dir_res:
            cli.command(name=product_name, help=f'Query {product_name}')(create_generic_product_command(str(product_name)))

    cli()