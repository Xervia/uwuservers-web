import requests

class mcAuth:
    def __init__(self):
        self.mcAuthUri = 'https://mc-auth.com/oAuth2/token'
    
    def proxy(self, mcAuthData):
        if 'client_id' not in mcAuthData or 'client_secret' not in mcAuthData or 'code' not in mcAuthData or 'redirect_uri' not in mcAuthData or 'grant_type' not in mcAuthData:
            return {'error': 'missing_required_data', 'status': 400}
        
        headers = {
            'Content-Type': 'application/json'
        }
        
        try:
            response = requests.post(self.mcAuthUri, json=mcAuthData, headers=headers)
            
            response.raise_for_status()
            
            result = {
                "uuid": response.json()['data']['uuid'],
                "name": response.json()['data']['profile']['name'],
            }
            
            return result
        except requests.exceptions.HTTPError as http_err:
            return {'error': str(http_err), 'status': response.status_code}
        except Exception as err:
            return {'error': str(err), 'status': 500}

# @app.route('/proxy', methods=['POST'])
# def proxy():
#     client_id = request.json.get('client_id')
#     client_secret = request.json.get('client_secret')
#     code = request.json.get('code')
#     redirect_uri = request.json.get('redirect_uri')
#     grant_type = request.json.get('grant_type')

#     post_data = {
#         'client_id': client_id,
#         'client_secret': client_secret,
#         'code': code,
#         'redirect_uri': redirect_uri,
#         'grant_type': grant_type
#     }

#     try:
#         response = requests.post('https://mc-auth.com/oAuth2/token', json=post_data, headers={
#             'Content-Type': 'application/json'
#         })

#         response.raise_for_status()
#         return jsonify(response.json()), response.status_code

#     except requests.exceptions.HTTPError as http_err:
#         return jsonify({"error": str(http_err), "message": response.text}), response.status_code

#     except Exception as err:
#         return jsonify({"error": str(err)}), 500