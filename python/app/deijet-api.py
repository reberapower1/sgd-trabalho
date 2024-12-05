##
## =============================================
## ======== Sistema de Gestão de Dados =========
## ============== LECD  2024/2025 ==============
## =============================================
## ============ Trabalho Prático ===============
## =============================================
## =============================================
## === DEpartamento de Engenharia Informática ===
## =========== University of Coimbra ===========
## =============================================
##
## Authors: Diana Martins
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
    'success': 200,
    'api_error': 400,
    'invalid_token': 401,
    'internal_error': 500
}

##########################################################
## DATABASE ACCESS
##########################################################

def db_connection():
    try:
        db = psycopg2.connect(user = "postgres",
                              password = "batata",
                              host = "localhost", #"db",
                              port = "5433",
                              database = "deijet")
        print("Conexão à base de dados estabelecida com sucesso!")
        return db
    except psycopg2.OperationalError as e:
        print(f"Erro ao conectar à base de dados: {e}")
        raise

# Função que verifica a password do utilizador
def verify_password(db_hash, provided_hash):
    provided_hash = hashlib.sha256(provided_hash.encode()).hexdigest()
    return db_hash == provided_hash

# Função que verifica chaves do payload
def verify_payload_keys(payload, keysNeeded):
    for key in keysNeeded:
        if key not in payload :
            response = {
                'status': StatusCodes ['api_error'],
                'message': f'{key} key not in client payload' 
            }
            return jsonify(response)

# Route da root
@app.route('/')
def root():
    return """
    <h1 style="color:DeepPink;"> DEIJET REST-API &#128747; </h1>
    <h2 style="color:Sienna"> Check out documentation for instructions on how to use the endpoints </p> 
    <h2 style="color:Sienna"> Developed by &#127872; Diana Martins &#127872; </p>
    """

# Route para registar o cliente
@app.route('/sgdproj/register/client', methods = ['POST'])
def register_client():
    logger.info('POST /sgdproj/register/user');   
    payload = request.get_json()
   
    conn = db_connection()
    # Definir o nível de isolamento da transação que envolve a compra
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_SERIALIZABLE)
    cur = conn.cursor()

    logger.info("---- Novo cliente  ----")
    logger.debug(f'payload: {payload}')

    keysNeededClient = ['username', 'password', 'nome', 'genero', 'data_nascimento', 'telefone','email']
    # Verificar chaves do payload
    for key in keysNeededClient:
        if key not in payload :
            response = {
                'status': StatusCodes ['api_error'],
                'message': f'{key} key not in client payload' 
            }
            return jsonify(response)
    
    # Encriptar a password 
    payload['password'] = hashlib.sha256(payload['password'].encode()).hexdigest()
    
    statement = 'call addClient(%s, %s, %s, %s, %s, %s, %s)'
    values = (payload['username'], payload['password'], payload['nome'], payload['genero'], payload['data_nascimento'], payload['telefone'], payload['email'])
    
    try:
        #Preencher os dados nas tabelas "utilizador" e "cliente"
        cur.execute(statement, values)
        # Confirmar a transação
        conn.commit()

        result = {
            'status': StatusCodes['success'],
            'message': 'Client registado com sucesso',
            'user': payload['username']
        }
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        conn.rollback()
        error_message = str(error).split('\n')[0]
        result = {
            'status': StatusCodes['internal_error'],
            'message': str(error_message)
        }
    finally:
        if conn is not None:
            cur.close()
            conn.close()

    return jsonify(result)

# Route para registar o administrador
@app.route('/sgdproj/register/admin', methods = ['POST'])
def register_admin():
    logger.info('POST /sgdproj/register/admin');   
    payload = request.get_json()

    # Verificar se o token do admin existe no payload
    if 'token' not in payload:
        response = {
            'status': StatusCodes['api_error'],
            'message': 'Token não existe'
        }
        return jsonify(response)
   
    conn = db_connection()
    # Definir o nível de isolamento da transação
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_SERIALIZABLE)
    cur = conn.cursor()

    logger.info("---- Novo  Admin  ----")
    logger.debug(f'payload: {payload}')

    admin_token = payload['token']

    # Verificar o admin token
    if not verify_admin_token(conn, admin_token):
        response = {
            'status': StatusCodes['invalid_token'],
            'message': 'Admin token inválido'
        }
        return jsonify(response)
    
    # # Verificar chaves do payload
    keysNeededAdmin = ['username', 'password', 'nome', 'genero', 'data_nascimento', 'telefone','email', 'funcao']
    for key in keysNeededAdmin:
        if key not in payload :
            response = {
                'status': StatusCodes ['api_error'],
                'message': f'{key} key not in admin payload' 
            }
            return jsonify(response)
    
    # Encriptar pass
    payload['password'] = hashlib.sha256(payload['password'].encode()).hexdigest()
    
    statement = 'call addAdmin(%s, %s, %s, %s, %s, %s, %s, %s, %s)'
    values = (payload['username'], payload['password'], payload['nome'], payload['genero'], payload['data_nascimento'], payload['telefone'], payload['email'], payload['funcao'], admin_username(admin_token))
    
    try:
        #Preencher os dados no utilizador e cliente
        cur.execute(statement, values)
        # Commitar as transações
        conn.commit()
        result = {
            'status': StatusCodes['success'],
            'message': 'Administrador registado com sucesso',
            'user': payload['username'],
            'token': generate_token(payload['username'], 'admin')
        }
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        conn.rollback()
        error_message = str(error).split('\n')[0]
        result = {
            'status': StatusCodes['internal_error'],
            'message': str(error_message)
        }
    finally:
        if conn is not None:
            cur.close()
            conn.close()
    
    return jsonify(result) 

# REGISTAR O TRIPULANTE
@app.route('/sgdproj/register/crew', methods = ['POST'])
def register_crew():
    logger.info('POST /sgdproj/register/crew');   
    payload = request.get_json()
   
    conn = db_connection()
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_SERIALIZABLE)
    cur = conn.cursor()

    logger.info("---- Novo tripulante  ----")
    logger.debug(f'payload: {payload}')
    # Check payload keys
    keysNeededCrew = ['username', 'password', 'nome', 'genero', 'data_nascimento', 'telefone','email', 'funcao']
    for key in keysNeededCrew:
        if key not in payload :
            response = {
                'status': StatusCodes ['api_error'],
                'message': f'{key} key not in crew payload' 
            }
            return jsonify(response)
        
    # Encrypt password
    payload['password'] = hashlib.sha256(payload['password'].encode()).hexdigest()
    statement = 'call addCrew(%s, %s, %s, %s, %s, %s, %s, %s)'
    values = (payload['username'], payload['password'], payload['nome'], payload['genero'], payload['data_nascimento'], payload['telefone'], payload['email'], payload['funcao'])
    
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
        error_message = str(error).split('\n')[0]
        conn.rollback()
        result = {
            'status': StatusCodes['internal_error'],
            'message': str(error_message)
        }
    finally:
        if conn is not None:
            cur.close()
            conn.close()
    return jsonify(result)

# Login Route
@app.route('/sgdproj/login', methods = ['PUT'])
def login():
    logger.info('PUT /sgdproj/login')
    logger.info("---- Login  ----")
    payload = request.get_json()
    keysNeededLogin = ['username', 'password']
    for key in keysNeededLogin:
        if key not in payload:
            response = {
                'status': StatusCodes['api_error'],
                'message': f'{key} value not in payload'
            }
            return jsonify(response)
        
    conn = db_connection()
    cursor = conn.cursor()

    payload['password'] = hashlib.sha256(payload['password'].encode()).hexdigest()

    statement = 'SELECT login(%s, %s)'
    values = (payload['username'], payload['password'])

    try:
        cursor.execute(statement, values)
        tipo_user, = cursor.fetchone() 
    
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        error_message = str(error).split('\n')[0]
        result = {
            'status': StatusCodes['internal_error'],
            'message': 'Internal error',
            'results':  f'Error: {error_message}'
        }
        return jsonify(result) 
    
    else:
        if tipo_user in [1,2]:
            role = 'user'
        elif tipo_user == 3:
            role = 'admin'
        
        token = generate_token (payload['username'], role )
        
        response = {
            'status': StatusCodes['success'],
            'message': 'Login successful',
            'token': token
        }
    
    finally:
        if conn is not None:
            cursor.close()
            conn.close()
    return jsonify(response)
    
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

def verify_admin_token(conn, token):
    decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
    username = decoded_token.get("username")
    role = decoded_token.get("role")
    
    if role != 'admin':
        return False, {"message": "Not an admin"}
    
    with conn.cursor() as cur:
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

def verify_auth_token(conn, token):
    decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
    username = decoded_token.get("username")
    role = decoded_token.get("role")
    if role != 'user' or role != 'admin':
        return False, {"message": "Not an valid user"}
    
    with conn.cursor() as cur:
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
    
def admin_username(token):
    # Decode token
    decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
    # Extract data from token
    username_criador = decoded_token.get("username")
    return username_criador

@app.route('/sgdproj/airport', methods = ['POST'])
def cria_aeroporto():
    logger.info('POST /sgdproj/airport');   
    logger.info("---- Novo aeroporto  ----")
    payload = request.get_json()
    logger.debug(f'payload: {payload}')
    
    # Verificar se o token existe no payload
    if 'token' not in payload:
        response = {
            'status': StatusCodes['api_error'],
            'message': 'Token não existe'
        }
        return jsonify(response)
   
    conn = db_connection()
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_SERIALIZABLE)
    cur = conn.cursor()
    
    # Admin token
    admin_token = payload['token']

    # Verify admin token
    if not verify_admin_token(conn, admin_token):
        response = {
            'status': StatusCodes['invalid_token'],
            'message': 'Admin token inválido'
        }
        return jsonify(response)
    
    keysNeededAirport = ['nome', 'cidade', 'pais', 'id']
    for key in keysNeededAirport:
        if key not in payload:
            response = {
                'status': StatusCodes['api_error'],
                'message': f'{key} value not in payload'
            }
            return jsonify(response)
        
    statement = 'call addAeroporto (%s,%s,%s,%s,%s)'
    values = (payload['nome'], payload['cidade'], payload['pais'], payload['id'], admin_username(admin_token))

    try:
        #Preencher os dados na tabela aeroporto
        cur.execute(statement, values)
        # Commitar as transações
        conn.commit()
        result = {
            'status': StatusCodes['success'],
            'message': 'Aeroporto criado com sucesso',
            'results': payload['id']
        }
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        conn.rollback()
        error_message = str(error).split('\n')[0]
        result = {
            'status': StatusCodes['internal_error'],
            'message': str(error_message)
        }
    finally:
        if conn is not None:
            cur.close()
            conn.close()
    
    return jsonify(result)

@app.route('/sgdproj/flight', methods = ['POST'])
def cria_voo():
    logger.info('POST /sgdproj/flight');   
    logger.info("---- Novo voo  ----")

    payload = request.get_json()

    logger.debug(f'payload: {payload}')
    
    # Verificar se o token existe no payload
    if 'token' not in payload:
        response = {
            'status': StatusCodes['api_error'],
            'message': 'Token não existe'
        }
        return jsonify(response)
   
    conn = db_connection()
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_SERIALIZABLE)
    cur = conn.cursor()
    
    # Admin token
    admin_token = payload['token']

    # Verificar admin token
    if not verify_admin_token(conn, admin_token):
        response = {
            'status': StatusCodes['invalid_token'],
            'message': 'Admin token inválido'
        }
        return jsonify(response)
    
    keysNeededFlight = ['capacidade', 'id', 'aeroporto_origem', 'aeroporto_destino']
    for key in keysNeededFlight:
        if key not in payload:
            response = {
                'status': StatusCodes['api_error'],
                'message': f'{key} value not in payload'
            }
            return jsonify(response)
    
    statement = ' call addVoo (%s, %s, %s, %s, %s)'
    values = (payload['capacidade'], payload['id'], admin_username(admin_token), payload['aeroporto_origem'], payload['aeroporto_destino'])

    try:
        #Preencher os dados na tabela voo
        cur.execute(statement, values)
        # Validar as transações
        conn.commit()
        result = {
            'status': StatusCodes['success'],
            'message': 'Voo criado com sucesso',
            'results':  payload['id']
        }
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        conn.rollback()
        error_message = str(error).split('\n')[0]
        result = {
            'status': StatusCodes['internal_error'],
            'message': str(error_message)
        }
    finally:
        if conn is not None:
            cur.close()
            conn.close()
    
    return jsonify(result)
        
@app.route('/sgdproj/schedule', methods = ['POST'])
def cria_horario():
    logger.info('POST /sgdproj/schedule');   
    logger.info("---- Novo horário  ----")

    payload = request.get_json()

    logger.debug(f'payload: {payload}')
    
    # Verificar se o token existe no payload
    if 'token' not in payload:
        response = {
            'status': StatusCodes['api_error'],
            'message': 'Token não existe'
        }
        return jsonify(response)
   
    conn = db_connection()
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_SERIALIZABLE)
    cur = conn.cursor()
    
    # Admin token
    admin_token = payload['token']

    # Verify admin token
    if not verify_admin_token(conn, admin_token):
        response = {
            'status': StatusCodes['invalid_token'],
            'message': 'Admin token inválido'
        }
        return jsonify(response)
    
    keysNeededSchedule = ['partida' ,'chegada','id','preco','voo_id']
    for key in keysNeededSchedule:
        if key not in payload:
            response = {
                'status': StatusCodes['api_error'],
                'message': f'{key} value not in payload'
            }
            return jsonify(response)
    
    statement = ' call addhorario (%s,%s,%s,%s,%s, %s)'
    values = (payload['partida'], payload['chegada'], payload['id'],payload['preco'] ,payload['voo_id'], admin_username(admin_token))

    try:
        #Preencher os dados na tabela horário
        cur.execute(statement, values)
        # Commitar as transações
        conn.commit()
        result = {
            'status': StatusCodes['success'],
            'message': 'Horário criado com sucesso',
            'results': payload['id']
        }
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        conn.rollback()
        error_message = str(error).split('\n')[0]
        result = {
            'status': StatusCodes['internal_error'],
            'message': str(error_message)
        }
    finally:
        if conn is not None:
            cur.close()
            conn.close()
    
    return jsonify(result)

@app.route('/sgdproj/check_routes', methods = ['GET'])
def checkar_rotas():
    logger.info('GET /sgdproj/check_routes');   
    logger.info("---- Rotas Disponíveis  ----")

    payload = request.get_json()

    logger.debug(f'payload: {payload}')
    
    # Verificar se o token existe no payload
    if 'token' not in payload:
        response = {
            'status': StatusCodes['api_error'],
            'message': 'Token não existe'
        }
        return jsonify(response)
   
    conn = db_connection()
    cur = conn.cursor()
    
    # token
    token = payload['token']

    # Verificar token
    if not verify_auth_token(conn, token):
        response = {
            'status': StatusCodes['invalid_token'],
            'message': 'Token inválido'
        }
        return jsonify(response)
    
    keysNeededSchedule = ['aeroporto_origem','aeroporto_destino']
    for key in keysNeededSchedule:
        if key not in payload:
            response = {
                'status': StatusCodes['api_error'],
                'message': f'{key} value not in payload'
            }
            return jsonify(response)
       
    statement = ' SELECT * from check_rotas (%s,%s)'
    values = (payload['aeroporto_origem'], payload['aeroporto_destino'])

    try:
        #Preencher os dados na tabela horário
        cur.execute(statement, values)

        # Obter os resultados
        linhas = cur.fetchall()
        colunas = [desc[0] for desc in cur.description]  # Obter os nomes das colunas

        # Formatando os resultados em um dicionário
        informacao = [dict(zip(colunas, linha)) for linha in linhas]

        # Retornar a resposta com os dados
        result = {
            'status': StatusCodes['success'],
            'results': informacao
        }

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        error_message = str(error).split('\n')[0]
        result = {
            'status': StatusCodes['internal_error'],
            'message': str(error_message)
        }
    finally:
        if conn is not None:
            cur.close()
            conn.close()
    
    return jsonify(result)

@app.route('/sgdproj/check_seats', methods = ['GET'])
def checkar_lugar():
    logger.info('GET /sgdproj/check_seats  ');   
    logger.info("---- Lugares Disponíveis  ----")

    payload = request.get_json()
    
    logger.debug(f'payload: {payload}')
    
    # Verificar se o token existe no payload
    if 'token' not in payload:
        response = {
            'status': StatusCodes['api_error'],
            'message': 'Token não existe'
        }
        return jsonify(response)
   
    conn = db_connection()
    cur = conn.cursor()
    
    # token
    token = payload['token']

    # Verificar token
    if not verify_auth_token(conn, token):
        response = {
            'status': StatusCodes['invalid_token'],
            'message': 'Token inválido'
        }
        return jsonify(response)
    
    keysNeededSchedule = ['voo_id','horario_id']
    for key in keysNeededSchedule:
        if key not in payload:
            response = {
                'status': StatusCodes['api_error'],
                'message': f'{key} value not in payload'
            }
            return jsonify(response)
       
    statement = ' SELECT * from check_seat (%s,%s)'
    values = (payload['voo_id'], payload['horario_id'])

    try:
        #Preencher os dados na tabela horário
        cur.execute(statement, values)
        informacao = cur.fetchone()[0]  

        # Retornar a resposta com os dados
        result = {
            'status': StatusCodes['success'],
            'results' : informacao
        }
  
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        error_message = str(error_message).split('\n')[0]
        result = {
            'status': StatusCodes['internal_error'],
            'message': str(error_message)
        }
    finally:
        if conn is not None:
            cur.close()
            conn.close()
    
    return jsonify(result)

@app.route('/sgdproj/book_flight', methods=['POST'])
def compra():
    logger.info('POST /sgdproj/book_flight')
    logger.info("---- Reservar um voo ----")

    payload = request.get_json()
    logger.debug(f'payload: {payload}')

    # Verificar se o token existe no payload
    if 'token' not in payload:
        response = {
            'status': StatusCodes['api_error'],
            'message': 'Token não existe'
        }
        return jsonify(response)
    
    # token
    token = payload['token']

    conn = db_connection()
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_SERIALIZABLE)
    cur = conn.cursor()
    
    # Verificar token
    if not verify_auth_token(conn, token):
        response = {
            'status': StatusCodes['invalid_token'],
            'message': 'Token inválido'
        }
        return jsonify(response)
    
    keysNeededBook =  ['horario_id', 'seats']
    for key in keysNeededBook:
        if key not in payload:
            response = {
                'status': StatusCodes['api_error'],
                'message': f'{key} value not in payload'
            }
            return jsonify(response)

    statement = 'call addCompra( %s, %s, %s)'
    values = (payload['horario_id'], admin_username(payload['token']), payload['seats'])
    try:
        cur.execute(statement, values)

        response = {
            'status': StatusCodes['success'],
            'results': {'schedule_id': payload['horario_id']}
        }

        conn.commit()

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        conn.rollback()  
        error_message = str(error).split('\n')[0]
        response = {
            'status': StatusCodes['internal_error'],
            'message': str(error_message)
        }

    finally:
        if conn is not None:
            cur.close()
            conn.close()

    return jsonify(response)

@app.route('/sgdproj/report/topDestinations/<int:n>', methods = ['GET'])
def n_destinos(n):
    logger.info('GET /sgdproj/report/topDestinations/<int:n>');   
    logger.info("---- Top destinos  ----")

    payload = request.get_json()
    
    logger.debug(f'payload: {payload}')
    
    # Verificar se o token existe no payload
    if 'token' not in payload:
        response = {
            'status': StatusCodes['api_error'],
            'message': 'Token não existe'
        }
        return jsonify(response)
   
    conn = db_connection()
    cur = conn.cursor()
    
    # token
    token = payload['token']

    # Verificar token
    if not verify_auth_token(conn, token):
        response = {
            'status': StatusCodes['invalid_token'],
            'message': 'Token inválido'
        }
        return jsonify(response)
       
    statement = ' SELECT * from top_destinos (%s)'
    values = ((n,))

    try:
        #Preencher os dados na tabela horário
        cur.execute(statement, values)
        tabela = cur.fetchall()  
        results = [{"aeroporto de destino": linha[0], "número de voos": linha[1]} for linha in tabela]

        # Retornar a resposta com os dados
        result = {
            'status': StatusCodes['success'],
            'results' : results
        }
  
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        error_message = str(error).split('\n')[0]
        result = {
            'status': StatusCodes['internal_error'],
            'message': str(error_message)
        }
    finally:
        if conn is not None:
            cur.close()
            conn.close()
    
    return jsonify(result)

@app.route('/sgdproj/report/topRoutes/<int:n>', methods=['GET'])
def top_rotas(n):
    logger.info('GET /sgdproj/report/topRoutes/<int:n>')
    logger.info("---- Top routes ----")

    payload = request.get_json()

    logger.debug(f'payload: {payload}')

    # Verificar se o token existe no payload
    if 'token' not in payload:
        response = {
            'status': 400,
            'message': 'Token não existe'
        }
        return jsonify(response)

    conn = db_connection()
    cur = conn.cursor()

    # token
    token = payload['token']

    # Verificar token
    if not verify_auth_token(conn, token):
        response = {
            'status': 400,
            'message': 'Token inválido'
        }
        return jsonify(response)

    statement = 'SELECT * FROM top_rotas(%s);'
    values = ((n,))

    try:
        cur.execute(statement, values)
        tabela = cur.fetchall()

        results = [{"mês": linha[0], "TopN": [{"id_voo": r[0], "total_passageiros": r[1]} for r in linha[1]]} for linha in tabela]

        result = {
            'status': 200,
            'results': results
        }

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        error_message = str(error).split('\n')[0]
        result = {
            'status': 500,
            'message': str(error_message)
        }
    finally:
        if conn is not None:
            cur.close()
            conn.close()

    return jsonify(result)



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
