import uuid
import mcp.types as types

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from starlette.requests import Request
from starlette.types import Scope

from mcp.shared.version import SUPPORTED_PROTOCOL_VERSIONS

class ProxyView(APIView):
    sessions = {}

    def post(self, request, session_id=None):
        try:
            body = request.data  # DRF auto-parses JSON body for you
            print(f"body: {body}")
            rpc_request = types.JSONRPCRequest.model_validate(body)
        except Exception as e:
            return Response(
                {"error": f"Invalid JSON-RPC request: {e}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        
        print(f"rpc_request.method: {rpc_request.method}")

        if rpc_request.method == "initialize":

            # create new session
            new_session_id = str(uuid.uuid4())
            self.sessions[new_session_id] = {}
            requested_version = rpc_request.params["protocolVersion"]
            print(f"requested_version: {requested_version}")

            init_result = types.InitializeResult(
                protocolVersion=requested_version,
                capabilities={
                    "supportsTools": True,
                    "supportsResources": True,
                },
                serverInfo={
                    "name": "MyMCPProxyServer",
                    "version": "0.1.0",
                },
                sessionId=new_session_id,
            )

            response = types.JSONRPCResponse(
                jsonrpc="2.0",
                id=rpc_request.id,
                result=init_result.model_dump(),
            )
            return Response(response.model_dump())

        # For non-initialize, require valid session_id
        if not session_id or session_id not in self.sessions:
            return Response(
                {"error": "Unknown or missing session ID"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # TODO: Add your session message handling logic here

        response = types.JSONRPCResponse(
            jsonrpc="2.0",
            id=rpc_request.id,
            result={"message": "Session message received"},
        )
        return Response(response.model_dump())

    def get(self, request, session_id):
        if not session_id or session_id not in self.sessions:
            return Response(
                {"error": "Unknown or missing session ID"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response({"detail": "GET streaming not implemented"}, status=501)

    def delete(self, request, session_id):
        if session_id in self.sessions:
            del self.sessions[session_id]
            return Response({"detail": "Session terminated"})
        else:
            return Response(
                {"error": "Unknown session"},
                status=status.HTTP_400_BAD_REQUEST,
            )

