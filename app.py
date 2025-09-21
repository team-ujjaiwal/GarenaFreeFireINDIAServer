from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import time
import random

app = Flask(__name__)

def load_tokens(server_name):
    try:
        if server_name == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
        elif server_name in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_uid, token, url, session, delay=0):
    try:
        if delay > 0:
            await asyncio.sleep(delay)
            
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        
        async with session.post(url, data=edata, headers=headers) as response:
            response_text = await response.text()
            if response.status != 200:
                app.logger.error(f"Request failed with status code: {response.status}, Response: {response_text}")
                return {"status": response.status, "token": token, "success": False}
            
            app.logger.info(f"Request successful for token: {token[:10]}...")
            return {"status": response.status, "token": token, "success": True}
            
    except Exception as e:
        app.logger.error(f"Exception in send_request for token {token[:10]}...: {e}")
        return {"status": "error", "token": token, "success": False, "error": str(e)}

async def send_multiple_requests(uid, server_name, url, batch_size=10, delay_between_batches=2):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message.")
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None
        
        tokens = load_tokens(server_name)
        if tokens is None:
            app.logger.error("Failed to load tokens.")
            return None
        
        results = []
        successful_requests = 0
        failed_requests = 0
        
        # Process tokens in batches to avoid overwhelming the server
        async with aiohttp.ClientSession() as session:
            for i in range(0, len(tokens), batch_size):
                batch = tokens[i:i+batch_size]
                batch_tasks = []
                
                for j, token_data in enumerate(batch):
                    token = token_data["token"]
                    # Add a small random delay between requests in the same batch (0.1-0.5 seconds)
                    individual_delay = random.uniform(0.1, 0.5) * j
                    batch_tasks.append(send_request(encrypted_uid, token, url, session, individual_delay))
                
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                results.extend(batch_results)
                
                # Count successful and failed requests
                for result in batch_results:
                    if isinstance(result, dict) and result.get("success"):
                        successful_requests += 1
                    else:
                        failed_requests += 1
                
                app.logger.info(f"Processed batch {i//batch_size + 1}/{(len(tokens)+batch_size-1)//batch_size}, "
                               f"Successful: {successful_requests}, Failed: {failed_requests}")
                
                # Add delay between batches if not the last batch
                if i + batch_size < len(tokens):
                    await asyncio.sleep(delay_between_batches)
        
        return {
            "total_requests": len(tokens),
            "successful_requests": successful_requests,
            "failed_requests": failed_requests,
            "detailed_results": results
        }
        
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        if decode is None:
            app.logger.error("Protobuf decoding returned None.")
        return decode
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server", "").upper()
    batch_size = int(request.args.get("batch_size", 10))
    batch_delay = float(request.args.get("batch_delay", 2))
    
    if not uid or not server_name:
        return jsonify({"error": "UID and server are required"}), 400

    try:
        def process_request():
            tokens = load_tokens(server_name)
            if tokens is None:
                raise Exception("Failed to load tokens.")
            token = tokens[0]['token']
            encrypted_uid = enc(uid)
            if encrypted_uid is None:
                raise Exception("Encryption of UID failed.")

            # Get initial like count
            before = make_request(encrypted_uid, server_name, token)
            if before is None:
                raise Exception("Failed to retrieve initial player info.")
            try:
                jsone = MessageToJson(before)
            except Exception as e:
                raise Exception(f"Error converting 'before' protobuf to JSON: {e}")
            data_before = json.loads(jsone)
            before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
            try:
                before_like = int(before_like)
            except Exception:
                before_like = 0
            app.logger.info(f"Likes before command: {before_like}")

            # Determine the like endpoint URL
            if server_name == "IND":
                url = "https://client.ind.freefiremobile.com/LikeProfile"
            elif server_name in {"BR", "US", "SAC", "NA"}:
                url = "https://client.us.freefiremobile.com/LikeProfile"
            else:
                url = "https://clientbp.ggblueshark.com/LikeProfile"

            # Send like requests with batching and delays
            like_results = asyncio.run(send_multiple_requests(uid, server_name, url, batch_size, batch_delay))
            
            # Wait a bit before checking the updated like count
            time.sleep(5)
            
            # Get updated like count
            after = make_request(encrypted_uid, server_name, token)
            if after is None:
                raise Exception("Failed to retrieve player info after like requests.")
            try:
                jsone_after = MessageToJson(after)
            except Exception as e:
                raise Exception(f"Error converting 'after' protobuf to JSON: {e}")
            data_after = json.loads(jsone_after)
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
            player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
            player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
            like_given = after_like - before_like
            status = 1 if like_given != 0 else 2
            
            # Prepare response
            response = {
                "response": {
                    "LikesGivenByAPI": like_given,
                    "LikesafterCommand": after_like,
                    "LikesbeforeCommand": before_like,
                    "PlayerNickname": player_name,
                    "UID": player_uid,
                    "TokensUsed": len(tokens),
                    "SuccessfulRequests": like_results.get("successful_requests", 0) if like_results else 0,
                    "FailedRequests": like_results.get("failed_requests", 0) if like_results else 0
                },
                "status": status
            }
            
            return response

        result = process_request()
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/verify_tokens', methods=['GET'])
def verify_tokens():
    server_name = request.args.get("server", "").upper()
    if not server_name:
        return jsonify({"error": "Server name is required"}), 400
    
    tokens = load_tokens(server_name)
    if tokens is None:
        return jsonify({"error": "Failed to load tokens"}), 500
    
    return jsonify({
        "server": server_name,
        "token_count": len(tokens),
        "tokens": tokens[:10]  # Return first 10 tokens for verification
    })

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)