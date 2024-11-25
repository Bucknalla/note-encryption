from flask import Flask, request
from decrypt import decrypt_data
import json

app = Flask(__name__)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    print("Decrypting data")
    
    encrypted_data = request.json
    
    # # Get encrypted data and signature from request
    # encrypted_data = request.json.get('encrypted_data')
    # signature = request.json.get('signature')
    
    # if not encrypted_data or not signature:
    #     return "Missing encrypted data or signature", 400
        
    try:
        decrypted_data = decrypt_data('../keys/privateKey.pem', encrypted_data)
        return decrypted_data.decode('utf-8'), 200
        
    except Exception as e:
        return f"Decryption failed: {str(e)}", 400

if __name__ == '__main__':
    print("Starting server")
    app.run(debug=True, port=4000)

