from rest_framework.response import Response

def resources_templates_list(request):
    """
    Handles 'resources/templates/list' RPC method.
    """
    return Response({
        'jsonrpc': '2.0',
        'id': request.data.get("id"),
        # 'result': result
        'result': {},
    })
    