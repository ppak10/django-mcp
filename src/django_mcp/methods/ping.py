from rest_framework.response import Response

def ping(request):
    try:
        return Response({
            'jsonrpc': '2.0',
            'id': request.data.get("id"),
            'result': {},
        })
    except Exception as e:
        return Response({
            'jsonrpc': '2.0',
            'id': request.data.get("id"),
            'error': {
                'code': -32603,
                'message': str(e),
            }
        })
