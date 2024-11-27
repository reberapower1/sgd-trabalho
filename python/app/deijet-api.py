##
## =============================================
## ======== Sistema de Gestão de Dados =========
## ============== LECD  2024/2025 ==============
## =============================================
## ============ Trabalho Prático ===============
## =============================================
## =============================================
## === Department of Informatics Engineering ===
## =========== University of Coimbra ===========
## =============================================
##
## Authors: 
##   


'''
How to run?
$ python3 -m venv proj_sgd_env
$ source proj_sgd_env/bin/activate
$ pip3 install flask
$ pip3 install jwt
$ pip3 install python-dotenv
$ pip3 install psycopg2-binary
$ python3 deijet-api.py
--> Ctrl+C to stop
$ deactivate
'''
import logging
import psycopg2
from flask import Flask, jsonify, request
import jwt
import hashlib
from dotenv import load_dotenv
import os
# Import env vars
load_dotenv()

app = Flask(__name__)

StatusCodes = {
    'sucess': 200,
    'api_error': 400,
    'invalid_token': 401,
    'unauthorized_access':403,
    'internal_error': 500
}

##########################################################
## DATABASE ACCESS
##########################################################

def db_connection():
    # NOTE: change the host to "db" if you are running as a Docker container
    db = psycopg2.connect(
        user = os.getenv("user"),
        password = os.getenv("password"),
        host = "localhost",
        port = "5432",
        database = "dbfichas"
    )
    return db

# Function that verify user password
def verify_password(db_hash, provided_hash):
    provided_hash = hashlib.sha256(provided_hash.encode()).hexdigest
    # Compare hashes
    return db_hash == provided_hash



@app.route('/sgdproj/user', methods = ['POST'])
def register_user():
    logger.info('POST /sgdproj/user');   
    payload = request.get_json()
    # Encrypt password
    payload['password'] = hashlib.sha256(payload['password'].encode()).hexdigest
    conn = db_connection()
    cur = conn.cursor()
    # CLient
    if len(payload) == 7:

        logger.info("---- New Client  ----")
        logger.debug(f'payload: {payload}')

        # Check payload keys
        keysNeededClient = ['username', 'password', 'nome', 'genero', 'data_nascimento', 'telefone','email']
        for key in keysNeededClient:
            if key not in payload :
                response = {
                    'status': StatusCodes ['api_error'],
                    'message': f'{key} key not in client payload' 
                }
                return jsonify(response)
        # Insert Payload in DB
        register_client(cur, conn, payload)

    # Admin
    elif len(payload) == 10 and ['token'] in payload:
        logger.info("---- New Admin  ----")
        logger.debug(f'payload: {payload}')
        # Admin token
        admin_token = payload['token']
        # Verify admin token
        if(verify_admin_token(cur, admin_token)):
            # Check payload keys
            keysNeededAdmin = ['username', 'password', 'nome', 'genero', 'data_nascimento', 'telefone','email', 'funcao','criado_por']
            for key in keysNeededAdmin:
                if key not in payload :
                    response = {
                        'status': StatusCodes ['api_error'],
                        'message': f'{key} key not in admin payload' 
                    }
                return jsonify(response)
            # Insert payload in DB
            register_admin(cur, conn, payload)
        # If token is invalid
        elif(verify_admin_token(cur, admin_token) == False):
            response = {
                    'status': StatusCodes ['invalid_token'],
                    'message': 'You do not have a valid admin token' 
            }
            return jsonify(response) 

    # Crew Member
    elif len(payload) == 10:
        logger.info("---- New Crew Member  ----")
        logger.debug(f'payload: {payload}')

        # Check payload keys
        keysNeededCrew = ['username', 'password', 'nome', 'genero', 'data_nascimento', 'telefone','email', 'funcao','horario','chefe']
        for key in keysNeededCrew:
            if key not in payload :
                response = {
                    'status': StatusCodes ['api_error'],
                    'message': f'{key} key not in crew payload' 
                }
                return jsonify(response)
        # Insert payload in DB
        register_crew_member(cur, conn, payload)
    else:
        response = {
            'status': StatusCodes ['api_error'],
            'message': 'Incorrect payload keys'
        }
        return jsonify(response)

def register_client(cur, conn, payload):
    # Define SQL statements
    insert_utilizador = """
        INSERT INTO utilizador (username, password, nome, genero, data_nascimento, telefone, email)
        VALUES (%s, %s, %s, %s, %s, %s, %s);
    """
    insert_cliente = """
        INSERT INTO cliente (utilizador_username)
        VALUES (%s);
    """

    # Extrair os valores do payload
    utilizador_values = (
        payload["username"],
        payload["password"],
        payload["nome"],
        payload["genero"],
        payload["data_nascimento"],
        payload["telefone"],
        payload["email"]
    )

    cliente_values = (payload["username"])

    try:
        # Inserir em 'utilizador'
        cur.execute(insert_utilizador, utilizador_values)
        # Inserir em 'cliente'
        cur.execute(insert_cliente, cliente_values)
        # Commitar as transações
        conn.commit()
        result = {
            'status': StatusCodes['success'],
            'message': 'Client registered successfully',
            'user': payload['username']
        }
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        conn.rollback()
        result = {
            'status': StatusCodes['db_error'],
            'message': str(error)
        }
    finally:
        if conn is not None:
            conn.close()

    return jsonify(result)

def register_admin(cur, conn, payload):
    # Define SQL statements
    insert_utilizador = """
        INSERT INTO utilizador (username, password, nome, genero, data_nascimento, telefone, email)
        VALUES (%s, %s, %s, %s, %s, %s, %s);
    """
    insert_admin = """
        INSERT INTO administrador (funcao, criado_por, utilizador_username)
        VALUES (%s, %s, %s);
    """

    # Extrair os valores do payload
    utilizador_values = (
        payload["username"],
        payload["password"],
        payload["nome"],
        payload["genero"],
        payload["data_nascimento"],
        payload["telefone"],
        payload["email"]
    )

    admin_values = (
        payload["funcao"],
        payload["criado_por"],
        payload["username"]
    )

    try:
        # Inserir em 'utilizador'
        cur.execute(insert_utilizador, utilizador_values)

        # Inserir em 'administrador'
        cur.execute(insert_admin, admin_values)

        # Commitar as transações
        conn.commit()

        result = {
            'status': StatusCodes['success'],
            'message': 'Admin registered successfully',
            'user': payload['username']
        }
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        conn.rollback()
        result = {
            'status': StatusCodes['db_error'],
            'message': str(error)
        }
    finally:
        if conn is not None:
            conn.close()

    return jsonify(result)

def register_crew_member(cur, conn, payload):
    # Define SQL statements
    insert_utilizador = """
        INSERT INTO utilizador (username, password, nome, genero, data_nascimento, telefone, email)
        VALUES (%s, %s, %s, %s, %s, %s, %s);
    """
    insert_tripulante = """
        INSERT INTO tripulante (funcao, horario_id, chefe, utilizador_username)
        VALUES (%s, %s, %s, %s);
    """

    # Extrair os valores do payload
    utilizador_values = (
        payload["username"],
        payload["password"],
        payload["nome"],
        payload["genero"],
        payload["data_nascimento"],
        payload["telefone"],
        payload["email"]
    )

    tripulante_values = (
        payload["funcao"],
        payload["horario_id"],
        payload["chefe"],
        payload["username"]
    )

    try:
        # Inserir em 'utilizador'
        cur.execute(insert_utilizador, utilizador_values)

        # Inserir em 'tripulante'
        cur.execute(insert_tripulante, tripulante_values)

        # Commitar as transações
        conn.commit()

        result = {
            'status': StatusCodes['success'],
            'message': 'Crew member registered successfully',
            'user': payload['username']
        }
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        conn.rollback()
        result = {
            'status': StatusCodes['db_error'],
            'message': str(error)
        }
    finally:
        if conn is not None:
            conn.close()

    return jsonify(result)

# Secret JWT Token
secret_key = os.getenv("secret_key")

# Generate Auth Token
def generate_auth_token(username):
    payload = {
        "username": username,
        "role": "user"
    }
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    return token

# Generate Admin Token
def generate_admin_token(username):
    payload = {
        "username": username,
        "role": "admin"
    }
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    return token

def verify_admin_token(cur, token):
    # Decode token
    decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
    # Extract data from token
    username = decoded_token.get("username")
    role = decoded_token.get("role")
    if role != 'admin':
        return False, {"message": "Not an admin"}
    query = """
    SELECT utilizador_username
    FROM administrador
    WHERE utilizador_username = %s;
    """
    cur.execute(query, (username,))
    admin_data = cur.fetchone()
    if admin_data:
        return True
    else:
        return False

def verify_auth_token(cur, token):
    # Decode token
    decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
    # Extract data from token
    username = decoded_token.get("username")
    role = decoded_token.get("role")
    if role != 'user':
        return False, {"message": "Not an valid user"}
    query = """
    SELECT username
    FROM utilizador
    WHERE username = %s;
    """
    cur.execute(query, (username,))
    user_data = cur.fetchone()
    if user_data:
        return True
    else:
        return False


if __name__ == '__main__':
    logging.basicConfig(filename="logs/log_file.log")
    logger = logging.getLogger('logger')