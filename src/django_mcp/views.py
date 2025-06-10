from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated, PermissionDenied
from rest_framework.views import APIView
from rest_framework.response import Response

from django_mcp.methods.ping import ping 
from django_mcp.methods.resources_list import resources_list
from django_mcp.methods.resources_templates_list import resources_templates_list
from django_mcp.methods.prompts_list import prompts_list
from django_mcp.methods.tools_list import tools_list

class MethodsView(APIView):
    permission_classes = []

    @classmethod
    def as_view(cls, **initkwargs):
        permissions = initkwargs.pop("permission_classes", None)
        view = super().as_view(**initkwargs)
        if permissions:
            view.cls.permission_classes = permissions
        return view
    
    def handle_exception(self, exc):
        if isinstance(exc, (NotAuthenticated, AuthenticationFailed, PermissionDenied)):
            return Response({
                'jsonrpc': '2.0',
                'error': {
                    'code': -32600,
                    'message': 'Forbidden: Authentication or permission denied.'
                },
                'id': None
            }, status=status.HTTP_403_FORBIDDEN)
        
        # fallback to DRF's default handler
        return super().handle_exception(exc)

    def is_valid_jsonrpc(self, data):
        return (
            isinstance(data, dict)
            and data.get("jsonrpc") == "2.0"
            and "method" in data
            and "id" in data
        )
    
    def method_not_found(self, data, not_implemented = False):
        message = f"Method not {'implemented yet.' if not_implemented else 'found.'}"
        return Response({
            'jsonrpc': '2.0',
            'error': {
                'code': -32601,
                'message': message
            },
            'id': data.get("id", None)
        }, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, *args, **kwargs):
        if not self.is_valid_jsonrpc(request.data):
            return Response({
                'jsonrpc': '2.0',
                'error': {
                    'code': -32600,
                    'message': 'Invalid Request'
                },
                'id': request.data.get("id", None)
            }, status=status.HTTP_400_BAD_REQUEST)

        method = request.data.get("method")

        if method == 'ping':
            return ping(request)
        elif method == 'resources/list':
            return resources_list(request)
        elif method == 'resources/templates/list':
            return resources_templates_list(request)
        elif method == 'prompts/list':
            return prompts_list(request)
        elif method == 'tools/list':
            return tools_list(request)
        else:
            return self.method_not_found(request.data, not_implemented=True)
        
    def get(self, request, *args, **kwargs):
        return Response({
            'jsonrpc': '2.0',
            'error': {
                'code': -32601,
                'message': 'GET method is not supported. Use POST with a valid JSON-RPC method.'
            },
            'id': None
        }, status=status.HTTP_405_METHOD_NOT_ALLOWED)
