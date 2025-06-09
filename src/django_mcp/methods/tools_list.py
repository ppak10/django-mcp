from rest_framework.response import Response

def tools_list(request):
    """
    Handles 'tools/list' RPC method.
    """
    return Response({
        'jsonrpc': '2.0',
        'id': request.data.get("id"),
        # 'result': result
        'result': {},
    })
    