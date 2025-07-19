import json

from mcp.shared.auth import ProtectedResourceMetadata


from rest_framework.views import APIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.permissions import AllowAny

class OAuthProtectedResourceView(APIView):
    """OAuth Authorization Server Metadata endpoint"""

    # TODO: Remove
    permission_classes = [AllowAny]
    
    def get(self, request: Request):
        metadata = self.build_metadata()

        return Response(
            headers={"Cache-Control": "public, max-age=3600"},
            data=json.loads(metadata.model_dump_json(exclude_none=True).encode("utf-8")),
        )
    
    def build_metadata(self):
        protected_resource_metadata = ProtectedResourceMetadata(
            resource="http://127.0.0.1:8002/",
            authorization_servers=["http://127.0.0.1:8002/"],
            scopes_supported=["user"],
        )

        return protected_resource_metadata

