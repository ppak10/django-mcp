from asgiref.sync import sync_to_async

from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated, PermissionDenied
from rest_framework.views import APIView
from rest_framework.response import Response

from django_mcp.methods.ping import ping 
from django_mcp.methods.completion_complete import completion_complete
from django_mcp.methods.resources_list import resources_list
from django_mcp.methods.resources_read import resources_read
from django_mcp.methods.resources_templates_list import resources_templates_list
from django_mcp.methods.server_capabilities import server_capabilities
from django_mcp.methods.prompts_list import prompts_list
from django_mcp.methods.tools_list import tools_list

class AsyncMethodsView(APIView):
    # Inside AsyncMethodsView
    @classmethod
    def as_view(cls, **initkwargs):
        permission_classes = initkwargs.pop("permission_classes", None)
        if permission_classes:
            cls.permission_classes = permission_classes

        view = super(AsyncMethodsView, cls).as_view(**initkwargs)
        view.cls = cls
        view.initkwargs = initkwargs

        async def async_view(request, *args, **kwargs):
            self = view.cls(**view.initkwargs)
            self.setup(request, *args, **kwargs)
            self.request = self.initialize_request(request)

            # Check permissions (sync wrapped)
            if hasattr(self, 'check_permissions'):
                await sync_to_async(self.check_permissions)(self.request)

            # Dispatch async handler
            response = await self.dispatch(self.request, *args, **kwargs)

            # ✅ FIX: Finalize response so DRF can render it correctly
            return self.finalize_response(self.request, response, *args, **kwargs)

        async_view.view_class = cls
        async_view.view_initkwargs = initkwargs
        async_view.cls = cls
        return async_view


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
        elif method == 'server/capabilities':
            return server_capabilities(request)
        elif method == 'completion/complete':
            return completion_complete(request)
        elif method == 'resources/list':
            return resources_list(request)
        elif method == 'resources/templates/list':
            return resources_templates_list(request)
        elif method == 'resources/read':
            return resources_read(request)
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
