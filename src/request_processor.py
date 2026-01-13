from urllib.parse import urlparse, parse_qs
import json

class RequestProcessor:
    def parse(self, request):
        return {
            'method': request.method,
            'path': request.path,
            'url': request.url,
            'headers': dict(request.headers),
            'args': dict(request.args),
            'form': dict(request.form) if request.form else {},
            'data': request.data.decode('utf-8', errors='ignore') if request.data else '',
            'suspicious_payload': self._extract_payload(request)
        }
    
    def _extract_payload(self, request):
        payload = ''
        payload += request.path + ' ' + request.url + ' '
        for k, v in request.args.items():
            payload += f"{k}={v} "
        for k, v in (request.form.items() if request.form else {}.items()):
            payload += f"{k}={v} "
        if request.data:
            payload += request.data.decode('utf-8', errors='ignore')
        return payload
