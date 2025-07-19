# views.py

from django.http import HttpResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt

SERVER_URL = "http://127.0.0.1:8002"  # Replace this with your actual server URL

@csrf_exempt  # Exempt from CSRF for demonstration; only do this in trusted/internal contexts
async def login_page(request):
    state = request.GET.get("state") if request.method == "GET" else request.POST.get("state")

    if not state:
        return HttpResponseBadRequest("Missing state parameter")

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MCP Demo Authentication</title>
        <style>
            body {{ font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; }}
            .form-group {{ margin-bottom: 15px; }}
            input {{ width: 100%; padding: 8px; margin-top: 5px; }}
            button {{ background-color: #4CAF50; color: white; padding: 10px 15px; border: none; cursor: pointer; }}
        </style>
    </head>
    <body>
        <h2>MCP Demo Authentication</h2>
        <p>This is a simplified authentication demo. Use the demo credentials below:</p>
        <p><strong>Username:</strong> demo_user<br>
        <strong>Password:</strong> demo_password</p>
        
        <form action="{SERVER_URL.rstrip("/")}/login/callback" method="post">
            <input type="hidden" name="state" value="{state}">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" value="demo_user" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" value="demo_password" required>
            </div>
            <button type="submit">Sign In</button>
        </form>
    </body>
    </html>
    """

    return HttpResponse(html_content, content_type="text/html")

