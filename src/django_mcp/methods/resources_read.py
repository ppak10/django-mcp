from rest_framework.response import Response

def resources_read(request):
    """
    Handles 'resources/read' RPC method.
    """
    return Response({
        'jsonrpc': '2.0',
        'id': request.data.get("id"),
        # 'result': result
        'result': {},
    })
    