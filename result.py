from flask import jsonify, request

def result(data, status=200):
    return jsonify({
        "data": data,
        "status": "success" if status == 200 else "error"
    }), status

def error(message, status=400):
    return result("error/" + message, status)

def checkJson(keysList):
    data = {}
    hasSomething = False
    
    for list in keysList:
        exists = True
        for key in list:
            if key['value'] not in request.json:
                exists = False
                break
            else:
                if type(request.json[key['value']]) != key['type']:
                    exists = False
                    break
        if exists:
            data = { key['value']: request.json[key['value']] for key in list }
            hasSomething = True
            break
    
    def clearType(type):
        return str(type).replace("<class '", '').replace("'>", '')
    
    if not hasSomething:
        errorHelp = '|'.join([ '&'.join([ key['value'] + ':' + clearType(key['type']) for key in list ]) for list in keysList ])
        data= { 'error': 'invalid_request/' + errorHelp }
    
    return data
        