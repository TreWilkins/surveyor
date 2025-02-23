from cbapi.response import CbEnterpriseResponseAPI # type: ignore
from cbapi.response.models import Process # type: ignore
import json
from common import Product, Tag, Result
from datetime import datetime
from typing import Optional


class CbResponse(Product):
    product: str = 'cbr'
    profile: str = 'default'
    url: Optional[str] = None
    token: Optional[str] = None
    _sensor_group: Optional[list[str]] = None
    _conn: CbEnterpriseResponseAPI  # CB Response API
    _limit: int = -1

    def __init__(self, **kwargs):
        self.profile = kwargs['profile'] if 'profile' in kwargs else 'default'
        self.url = kwargs['url'] if 'url' in kwargs else None
        self.token = kwargs['token'] if 'token' in kwargs else None
        self._sensor_group = kwargs['sensor_group'] if 'sensor_group' in kwargs else None
        self._limit = int(kwargs['limit']) if 'limit' in kwargs else self._limit

        super().__init__(self.product, **kwargs)

    def _authenticate(self) -> None:
        if self.token and self.url:
            cb_conn = CbEnterpriseResponseAPI(token=self.token, url=self.url)
        elif self.profile:
            cb_conn = CbEnterpriseResponseAPI(profile=self.profile)
        else:
            cb_conn = CbEnterpriseResponseAPI()

        self._conn = cb_conn

    def build_query(self, filters: dict) -> str:
        query_base = ''

        for key, value in filters.items():
            if key == 'days':
                query_base += ' start:-%dm' % (value * 1440)
            elif key == 'minutes':
                query_base += ' start:-%dm' % value
            elif key == 'hostname':
                query_base += ' hostname:%s' % value
            elif key == 'username':
                query_base += ' username:%s' % value
            else:
                self.log.warning(f'Query filter {key} is not supported by product {self.product}')

        if self._sensor_group:
            sensor_group = []
            for name in self._sensor_group:
                sensor_group.append('group:"%s"' % name)            
            query_base += ' (' + ' OR '.join(sensor_group) + ')'
        
        return query_base

    def process_search(self, tag: Tag, base_query: dict, query: str) -> None:
        #raw_results = list()
        results = set()

        query = query + self.build_query(base_query)
        self.log.info(query)

        try:
            # noinspection PyUnresolvedReferences
            for proc in self._conn.select(Process).where(query):
                result = Result(
                    hostname=proc.hostname.lower(), 
                    username=proc.username.lower(), 
                    path=proc.path, 
                    command_line=proc.cmdline, 
                    timestamp = self.cbr_convertime_iso8601(proc.start),
                    query=query,
                    program=tag.tag,
                    profile=self.profile,
                    raw_data=(json.dumps(proc.original_document))
                    )

                results.add(result)

                if self._limit > 0 and len(results)+1 > self._limit:
                        break
                
        except KeyboardInterrupt:
            self.log.info("Caught CTRL-C. Returning what we have . . .")
        
        self._add_results(list(results), tag)

    def nested_process_search(self, tag: Tag, criteria: dict, base_query: dict) -> None:
        results = set()

        try:
            for search_field, terms in criteria.items():
                if search_field == 'query':
                    if isinstance(terms, list):
                        if len(terms) > 1:
                            query = '((' + ') OR ('.join(terms) + '))'
                        else:
                            query = '(' + terms[0] + ')'
                    else:
                        query = terms
                else:
                    terms = [(f'"{term}"' if ' ' in term else term) for term in terms]

                    query = '(' + ' OR '.join('%s:%s' % (search_field, term) for term in terms) + ')'

                query += self.build_query(base_query)
                
                self.log.debug(f'Query: {query}')
                # noinspection PyUnresolvedReferences
                for proc in self._conn.select(Process).where(query):
                    result = Result(
                        hostname=proc.hostname.lower(), 
                        username=proc.username.lower(), 
                        path=proc.path, 
                        command_line=proc.cmdline, 
                        timestamp = proc.start, 
                        program=tag.tag,
                        profile=self.profile,
                        query=query,
                        raw_data=(json.dumps(proc.original_document))
                        )
                    results.add(result)
                    if self._limit > 0 and len(results)+1 > self._limit:
                        break
                    
        except Exception as e:
            self.log.exception(e)
            pass
        except KeyboardInterrupt:
            self.log.exception("Caught CTRL-C. Returning what we have . . .")

        self._add_results(list(results), tag)

    def cbr_convertime_iso8601(self, time:str) -> str:
        time = str(time)
        
        try:
            # Convert the input string to a datetime object
            time = datetime.strptime(time, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            try:
                time = datetime.strptime(time, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return time
        
        return time