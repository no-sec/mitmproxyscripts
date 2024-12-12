from mitmproxy import http
import requests
from requests_kerberos import HTTPKerberosAuth

def request(flow: http.HTTPFlow):
    # add kerberos authentication
    if flow.request.pretty_host == "<host that needs kerberos auth>":
        url = flow.request.url
        method = flow.request.method
        headers = flow.request.headers
        data = flow.request.text
        session = requests.Session()
        response = session.request(method=method, url=url, headers=headers, data=data, verify=False, auth=HTTPKerberosAuth())
        flow.response = http.Response.make(
                response.status_code,
                response.content,
                dict(response.headers)
        )
        return flow.response
