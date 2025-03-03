from datetime import datetime, timezone, timedelta
import json
import concurrent.futures # type: ignore
from typing import Generator, Optional
import cbc_sdk.errors # type: ignore
from cbc_sdk.rest_api import CBCloudAPI # type: ignore
from cbc_sdk.platform import Process # type: ignore
from cbc_sdk.base import QueryBuilder # type: ignore

from common import Product, Result, Tag

PARAMETER_MAPPING: dict[str, str] = {
    'process_name': 'process_name',
    'ipaddr': 'netconn_ipv4',
    'ipport': 'netconn_port',
    'cmdline': 'process_cmdline',
    'digsig_publisher': 'process_publisher',
    'domain': 'netconn_domain',
    'internal_name': 'process_internal_name',
    'md5':'hash',
    'sha256':'hash',
    'regmod':'regmod_name'
}

def _convert_relative_time(relative_time: str) -> str:
    """
    Convert a Cb Response relative time boundary (i.e., start:-1440m) to a device_timestamp:
    device_timestamp:[2019-06-02T00:00:00Z TO 2019-06-03T23:59:00Z]
    """
    time_format = "%Y-%m-%dT%H:%M:%SZ"
    minus_minutes = relative_time.split(':')[1].split('m')[0].split('-')[1]
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=int(minus_minutes))
    device_timestamp = 'device_timestamp:[{0} TO {1}]'.format(start_time.strftime(time_format),
                                                              end_time.strftime(time_format))
    return device_timestamp


class CbEnterpriseEdr(Product):
    product: str = 'cbc'
    profile: str = "default"
    token: Optional[str] = None
    org_key: Optional[str] = None
    futures: list[concurrent.futures.Future] = list()
    _device_group: Optional[list[str]] = None
    _device_policy: Optional[list[str]] = None  
    _conn: CBCloudAPI  # CB Cloud API
    _limit: int = -1

    def __init__(self, **kwargs):
        self.url = kwargs['url'] if 'url' in kwargs else None
        self.token = kwargs['token'] if 'token' in kwargs else None
        self.profile = kwargs['profile'] if 'profile' in kwargs else 'default'
        self.org_key = kwargs['org_key'] if 'org_key' in kwargs else None
        self._device_group = kwargs['device_group'] if 'device_group' in kwargs else None
        self._device_policy = kwargs['device_policy'] if 'device_group' in kwargs else None
        self._limit = int(kwargs['limit']) if 'limit' in kwargs else self._limit

        super().__init__(self.product, **kwargs)
        if isinstance(self.futures, list) and self.futures:
            self.log.warning(f"There appears to be {len(self.futures)} futures. There should be none on initialization. Investigate further to see if there is downstream corruption or impact.")
            self.futures.clear() # Clear out any previous futures

    def _authenticate(self) -> None:
        if self.token and self.url and self.org_key:
            cb_conn = CBCloudAPI(token=self.token, url=self.url, org_key = self.org_key)
        elif self.profile:
            cb_conn = CBCloudAPI(profile=self.profile)
        else:
            cb_conn = CBCloudAPI()

        self._conn = cb_conn

    def build_query(self, filters: dict) -> QueryBuilder:
        query_base = QueryBuilder()

        for key, value in filters.items():
            if key == "days":
                minutes_back = f'start:-{value * 1440}m'
                minutes_back = _convert_relative_time(minutes_back)
                query_base.and_(minutes_back)
            elif key == "minutes":
                minutes_back = f'start:-{value}m'
                minutes_back = _convert_relative_time(minutes_back)
                query_base.and_(minutes_back)
            elif key == "hostname":
                device_name = f'device_name:{value}'
                query_base.and_(device_name)
            elif key == "username":
                user_name = f'process_username:{value}'
                query_base.and_(user_name)
            else:
                self.log.warning(f'Query filter {key} is not supported by product {self.product}')

        if self._device_group:
            device_group = []
            for name in self._device_group:
                device_group.append(f'device_group:"{name}"')
            query_base.and_('(' + ' OR '.join(device_group) + ')')

        if self._device_policy:
            device_policy = []
            for name in self._device_policy:
                device_policy.append(f'device_policy:"{name}"')
            query_base.and_('(' + ' OR '.join(device_policy) + ')')

        return query_base

    def divide_chunks(self, l: list, n: int) -> Generator:
        for i in range(0, len(l), n):
            yield l[i:i + n]

    def perform_query(self, tag: Tag, base_query: dict, query: str) -> None:
        count = 0
        parsed_base_query = self.build_query(base_query)
        full_query = parsed_base_query.and_(f'({query})')
        full_query_str = " ".join(full_query._raw_query)
        self.current_query = full_query_str # This is set for Query Validator to reference.
        self.log.debug(f'Full Query: {full_query_str}')

        process = self._conn.select(Process)
        
        # If limit is set, tell CbC to only return that many rows per batch, allowing us to stop once we've reached the requested limit.
        if self._limit > 0:
            process.set_rows(self._limit)
        
        if not self._results.get(tag):
            self._results[tag] = [] 
        
        try:
            # noinspection PyUnresolvedReferences
            for proc in process.where(full_query):
                deets = proc.get_details()
                try:
                
                    result = Result(
                        hostname=deets.get('device_name'), 
                        username=deets['process_username'][0] if 'process_username' in deets else 'None', 
                        path=deets.get('process_name'), 
                        command_line=deets['process_cmdline'][0] if 'process_cmdline' in deets else 'None', 
                        timestamp=deets.get('process_start_time', deets.get('device_timestamp')),
                        query=" ".join(full_query._raw_query),
                        label=tag.tag,
                        profile=self.profile,
                        product=self.product,
                        source=tag.source,
                        raw_data=(json.dumps(deets)) # type:ignore
                        )
                    
                    self._results[tag].append(result)
                except Exception as e:
                    self.log.exception(f'Error processing result: {e}')
                    
                if self._limit > 0 and count >= (self._limit-1):
                    break
                count += 1

        except cbc_sdk.errors.ApiError as e:
            self.log.error(f'CbC SDK Error (see log for details): {e}')
        except KeyboardInterrupt:
            self.log.exception("Caught CTRL-C. Returning what we have . . .")
        
    def process_search(self, tag: Tag, base_query: dict, query: str) -> None:        
        self.perform_query(tag, base_query, query)

    def nested_process_search(self, tag: Tag, criteria: dict, base_query: dict) -> None:
        queries = []
        grouped_queries = [] # Used to group queries that have less than 100 terms, to speed up the search, all other queries will be run separately from the `queries` list (e.g. queries with more than 100 terms, or searches distinctly set as `query` in the search criteria) of a definition file.

        for search_field, terms in criteria.items():
            if search_field == 'query':
                if isinstance(terms, list):
                    if len(terms) > 1:
                        query = '(('+ ') OR ('.join(terms) + '))'
                    else:
                        query = '(' + terms[0] + ')'
                else:
                    query = terms
                queries.append(query)
            else:
                chunked_terms = list(self.divide_chunks(terms, 100))

                for chunk in chunked_terms:
                    # quote terms with spaces in them
                    terms = [(f'"{term}"' if ' ' in term else term) for term in chunk]

                    if search_field not in PARAMETER_MAPPING:
                        self.log.warning(f'Query filter {search_field} is not supported by product {self.product}')
                        continue

                    query = '(' + ' OR '.join('%s:%s' % (PARAMETER_MAPPING[search_field], term) for term in terms) + ')'
                    
                    if len(terms) >= 100: # Run the query by itself
                        queries.append(query) 
                    else:  # Group the query with others to run together
                        grouped_queries.append(query)
        
        if grouped_queries:
            if len(grouped_queries) > 1: # If there are multiple queries, group them together and then add them to the main list of queries
                queries.append('(' + ' OR '.join(grouped_queries) + ')')
            else:
                queries.extend(grouped_queries) # If there is only one query, add it to the main list of queries

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                for q in queries:
                    self.futures.append(executor.submit(self.perform_query, tag, base_query, q))
        except Exception as e:
            self.log.exception(e)


    def get_results(self, final_call: bool = True) -> dict[Tag, list[Result]]:
        if final_call:
            try:
                # Wait for all queries to complete, giving each 240 seconds to complete
                done, not_done = concurrent.futures.wait(self.futures, timeout=240, return_when=concurrent.futures.ALL_COMPLETED)
                
                if not_done: 
                    self.log.warning(f"Queries did not complete: {not_done}")
                self.log.debug(f"Queries completed: {len(done)}. Incompleted: {len(not_done)}")
            except Exception as e:
                self.log.error(f"Error while waiting for queries: {e}")

        return self._results