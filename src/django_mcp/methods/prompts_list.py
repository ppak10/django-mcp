from rest_framework.response import Response

def prompts_list(request):
    """
    Handles 'prompts/list' RPC method.
    """
    return Response({
        'jsonrpc': '2.0',
        'id': request.data.get("id"),
        # 'result': result
        'result': {},
    })
    