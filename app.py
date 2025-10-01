from flask import Flask, jsonify
from flasgger import Swagger

app = Flask(__name__)
swagger = Swagger(app)

@app.route('/login')
def login():
  """
  Autentica a un usuario.
  - Recibe: usuario, contraseña
  - Devuelve: Verifica hash y devuelve token JWT
  """
  return jsonify({'success': True}), 200


@app.route('/register')
def register():
  """
  Crea un usuario.
  - Recibe: usuario, contraseña
  - Devuelve: Guarda usuario y hash de la contraseña
  """
  return jsonify({'success': True}), 200


@app.route('/encrypt')
def encrypt():
  """
  Cifra un mensaje.
  - Recibe: plaintext
  - Devuelve: ciphertext, nonce, tag
  """
  return jsonify({'success': True}), 200


@app.route('/decrypt')
def decrypt():
  """
  Descifra un mensaje.
  - Recibe: ciphertext, nonce, tag
  - Devuelve: plaintext
  """
  return jsonify({'success': True}), 200


@app.route("/hmac", methods=["POST"])
def hmac_generate():
  """
  Genera/verifica un HMAC.
  - Recibe: message
  - Devuelve: hmac generado
  (en versión extendida: validar el hmac que envía el cliente).
  """
  return jsonify({"success": True, "hmac": ""}), 200


@app.route("/messages", methods=["POST"])
def create_message():
  """
  Crea un mensaje
  - Recibe: message, from, to
  - Devuelve: 
  """
  return jsonify({"success": True}), 200

@app.route("/messages", methods=["GET"])
def list_messages():
  """
  Devuelve los mensajes de un usuario
  - Recibe: from
  - Devuelve: messages[]
  """
  return jsonify({"success": True, "messages": []}), 200

if __name__ == '__main__':
  app.run(host="0.0.0.0", port=5000)
