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
## Authors: Divah
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
import time
import logging
import psycopg2
from flask import Flask, request, jsonify
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
    try:
        db = psycopg2.connect(
            user="deijet",
            password="tapsocialista",
            host="db",
            port="5432",
            database="db_deijet"
        )
        print("Conexão à base de dados estabelecida com sucesso!")
        return db
    except psycopg2.OperationalError as e:
        print(f"Erro ao conectar à base de dados: {e}")
        raise

# Function that verify user password
def verify_password(db_hash, provided_hash):
    provided_hash = hashlib.sha256(provided_hash.encode()).hexdigest()
    # Compare hashes
    return db_hash == provided_hash

#fazer uma para o início

#ESTE É O DO CLIENTE
@app.route('/sgdproj/register/client', methods = ['POST'])
def register_user():
    logger.info('POST /sgdproj/register/user');   
    payload = request.get_json()
   
    conn = db_connection()
    cur = conn.cursor()

    logger.info("---- Novo cliente  ----")
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
    
    # Encrypt password
    payload['password'] = hashlib.sha256(payload['password'].encode()).hexdigest()
    
    statement = 'call addClient(%s, %s, %s, %s, %s, %s, %s)'
    values = (payload['username'], payload['password'], payload['nome'], payload['genero'], payload['data_nascimento'], payload['telefone'], payload['email'])
    
    try:
        #Preencher os dados no utilizador e cliente
        cur.execute(statement, values)
        # Commitar as transações
        conn.commit()

        result = {
            'status': StatusCodes['success'],
            'message': 'Client registado com sucesso',
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
            cur.close()
            conn.close()

    return jsonify(result)

# REGISTAR O  Admin
@app.route('/sgdproj/register/admin', methods = ['POST'])
def register_user():
    logger.info('POST /sgdproj/register/admin');   
    payload = request.get_json()
   
    conn = db_connection()
    cur = conn.cursor()

    logger.info("---- Novo  Admin  ----")
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
        
        # Encrypt password
        payload['password'] = hashlib.sha256(payload['password'].encode()).hexdigest()

        statement = 'call addAdmin(%s, %s, %s, %s, %s, %s, %s)'
        values = (payload['username'], payload['password'], payload['nome'], payload['genero'], payload['data_nascimento'], payload['telefone'], payload['email'])

        try:
            #Preencher os dados no utilizador e cliente
            cur.execute(statement, values)
            # Commitar as transações
            conn.commit()

            result = {
                'status': StatusCodes['success'],
                'message': 'Client registado com sucesso',
                'user': payload['username'],
                'token': generate_token(payload['username'], 'admin')
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
                cur.close()
                conn.close()

        return jsonify(result)
    

    # If token is invalid
    elif(verify_admin_token(cur, admin_token) == False):
        response = {
                'status': StatusCodes ['invalid_token'],
                'message': 'You do not have a valid admin token' 
        }
        return jsonify(response) 

# REGISTAR O TRIPULANTE
@app.route('/sgdproj/register/crew', methods = ['POST'])
def register_user():
    logger.info('POST /sgdproj/register/admin');   
    logger.info("---- Novo tripulante  ----")
    logger.debug(f'payload: {payload}')
    payload = request.get_json()
    conn = db_connection()
    cur = conn.cursor()
    # Check payload keys
    keysNeededCrew = ['username', 'password', 'nome', 'genero', 'data_nascimento', 'telefone','email', 'funcao','tripulante_utilizador_username']
    for key in keysNeededCrew:
        if key not in payload :
            response = {
                'status': StatusCodes ['api_error'],
                'message': f'{key} key not in crew payload' 
            }
            return jsonify(response)
        
    # Encrypt password
    payload['password'] = hashlib.sha256(payload['password'].encode()).hexdigest()
    statement = 'call addCrew(%s, %s, %s, %s, %s, %s, %s, %s, %s)'
    values = (payload['username'], payload['password'], payload['nome'], payload['genero'], payload['data_nascimento'], payload['telefone'], payload['email'], payload['funcao'], payload['tripulante_utilizador_username'])
    
    try:
        #Preencher os dados no utilizador e tripulante
        cur.execute(statement, values)
        # Commitar as transações
        conn.commit()
        result = {
            'status': StatusCodes['success'],
            'message': 'Tripulante registado com sucesso',
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
            cur.close()
            conn.close()
    return jsonify(result)

# Login Route
@app.route('/sgdproj/login', methods = ['GET'])
def login():
    logger.info('GET /sgdproj/login')
    if 

# Secret JWT Token
secret_key = os.getenv("secret_key")

# Generate Auth Token
def generate_token(username, role):
    payload = {
        "username": username,
        "role": role
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
    # Caminho do diretório para os logs
    log_dir = "logs"
    log_file = os.path.join(log_dir, "log_file.log")
    # Verifique se o diretório existe, caso contrário, crie-o
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    logging.basicConfig(filename=log_file, level=logging.INFO)
    logger = logging.getLogger('logger')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter('%(asctime)s [%(levelname)s]:  %(message)s',
                              '%H:%M:%S')
                              # "%Y-%m-%d %H:%M:%S") # not using DATE to simplify
    ch.setFormatter(formatter)
    logger.addHandler(ch)


    time.sleep(1) # just to let the DB start before this print :-)


    logger.info("\n---------------------------------------------------------------\n" + 
                  "API v1.0 online: http://127.0.0.1:5000\n\n")


    
    # NOTE: change to 5000 or remove the port parameter if you are running as a Docker container
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
