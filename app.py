from flask import Flask, render_template, send_from_directory, render_template_string, send_file, request, jsonify
from api import Api
import flask_cors
import requests
import os

app = Flask(__name__, static_url_path="", static_folder="build", template_folder="build")
flask_cors.CORS(app, resources={r"/*": {"origins": "*"}})

api = Api(app)

@app.route('/proxy', methods=['POST'])
def proxy():
    client_id = request.json.get('client_id')
    client_secret = request.json.get('client_secret')
    code = request.json.get('code')
    redirect_uri = request.json.get('redirect_uri')
    grant_type = request.json.get('grant_type')

    post_data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code,
        'redirect_uri': redirect_uri,
        'grant_type': grant_type
    }

    try:
        response = requests.post('https://mc-auth.com/oAuth2/token', json=post_data, headers={
            'Content-Type': 'application/json'
        })

        response.raise_for_status()
        return jsonify(response.json()), response.status_code

    except requests.exceptions.HTTPError as http_err:
        return jsonify({"error": str(http_err), "message": response.text}), response.status_code

    except Exception as err:
        return jsonify({"error": str(err)}), 500

@app.route('/')
@app.route('/<first>')
@app.route('/<first>/<path:rest>')
def fallback(first="", rest=""):
    if rest == "" and first and os.path.exists(os.path.join(app.static_folder, first)):
        return send_file(os.path.join(app.static_folder, first))
    elif rest and os.path.exists(os.path.join(app.static_folder, "%s/%s" % (first, rest))):
        return send_file(os.path.join(app.static_folder, "%s/%s" % (first, rest)))
    else:
        return send_file('build/index.html')