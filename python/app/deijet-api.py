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
        db = psycopg2.connect(user = os.getenv("user"),
                              password = os.getenv("password"),
                              host = os.getenv("host"),
                              port = os.getenv("port"),
                              database = os.getenv("database")
                            )
        print("Conexão à base de dados estabelecida com sucesso!")
        return db
    except psycopg2.OperationalError as e:
        print(f"Erro ao conectar à base de dados: {e}")
        raise

# Função que verifica chaves do payload
def verify_payload_keys(payload, keysNeeded):
    for key in keysNeeded:
        if key not in payload :
            response = {
                'status': StatusCodes ['api_error'],
                'message': f'{key} key not in payload' 
            }
            return response
    return None

# Função que encripta a password
def encrypt_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


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
    response = verify_payload_keys(payload, keysNeededClient)
    if response :
        return jsonify(response)
    
    # Encriptar a password 
    payload['password'] = encrypt_password(payload['password'])
    
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

    # Verificar chaves do payload
    keysNeededAdmin = ['username', 'password', 'nome', 'genero', 'data_nascimento', 'telefone','email', 'funcao', 'token']
    response = verify_payload_keys(payload, keysNeededAdmin)
    if response:
        return jsonify(response)
    
    admin_token= payload['token']

    conn = db_connection()
    # Definir o nível de isolamento da transação
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_SERIALIZABLE)
    cur = conn.cursor()

    logger.info("---- Novo  Admin  ----")
    logger.debug(f'payload: {payload}')

    # Verificar o admin token
    if not verify_admin_token(conn, admin_token):
        response = {
            'status': StatusCodes['invalid_token'],
            'message': 'Admin token inválido'
        }
        return jsonify(response)
    
    # Encriptar a password
    payload['password'] = encrypt_password(payload['password'])
    
    statement = 'call addAdmin(%s, %s, %s, %s, %s, %s, %s, %s, %s)'
    values = (payload['username'], payload['password'], payload['nome'], payload['genero'], payload['data_nascimento'], payload['telefone'], payload['email'], payload['funcao'], get_username(admin_token))
    
    try:
        #Preencher os dados na tabela do utilizador e cliente
        cur.execute(statement, values)
        # Confirmar as transações
        conn.commit()
        result = {
            'status': StatusCodes['success'],
            'message': 'Administrador registado com sucesso',
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

# Route para registar o tripulante
@app.route('/sgdproj/register/crew', methods = ['POST'])
def register_crew():
    logger.info('POST /sgdproj/register/crew');   
    payload = request.get_json()
   
    conn = db_connection()
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_SERIALIZABLE)
    cur = conn.cursor()

    logger.info("---- Novo tripulante  ----")
    logger.debug(f'payload: {payload}')
    #Verificar payload
    keysNeededCrew = ['username', 'password', 'nome', 'genero', 'data_nascimento', 'telefone','email', 'funcao']
    response = verify_payload_keys (payload, keysNeededCrew)
    if response :
        return jsonify(response)
        
    # Encriptar a password
    payload['password'] = encrypt_password(payload['password'])
    statement = 'call addCrew(%s, %s, %s, %s, %s, %s, %s, %s)'
    values = (payload['username'], payload['password'], payload['nome'], payload['genero'], payload['data_nascimento'], payload['telefone'], payload['email'], payload['funcao'])
    
    try:
        #Preencher os dados na tabela do utilizador e tripulante
        cur.execute(statement, values)
        # Confirmar as transações
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

# Route para fazer login
@app.route('/sgdproj/login', methods = ['PUT'])
def login():
    logger.info('PUT /sgdproj/login')
    logger.info("---- Login  ----")
    payload = request.get_json()
    
    keysNeededLogin = ['username', 'password']
    response = verify_payload_keys (payload, keysNeededLogin)
    if response :
        return jsonify(response)  
    
    conn = db_connection()
    cursor = conn.cursor()

    payload['password'] = encrypt_password(payload['password'])

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
            'message': 'Login sucedido',
            'token': token
        }
    
    finally:
        if conn is not None:
            cursor.close()
            conn.close()
    return jsonify(response)
    
# Chave secreta para encrpitar o token (jwt)
secret_key = os.getenv("secret_key")

# Gerar Token
def generate_token(username, role):
    payload = {
        "username": username,
        "role": role
    }
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    return token

#Função para verificar o token do admin
def verify_admin_token(conn, token):
    resposta = None
    try:
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
    except jwt.DecodeError: 
        resposta = {"message": "Token inválido."} 
        return False, resposta
    
def verify_client_token(conn, token):
    resposta = None
    try:
        decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
        username = decoded_token.get("username")
        role = decoded_token.get("role")
        
        if role != 'client':
            return False, {"message": "Not an client"}
        
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
    except jwt.DecodeError: 
        resposta = {"message": "Token inválido."} 
        return False, resposta

#Função para verificar o token de autenticação
def verify_auth_token(conn, token):
    resposta = None
    try: 
        decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
        username = decoded_token.get("username")
        role = decoded_token.get("role")
        if role != 'user' or role != 'admin':
            return False, {"message": "User inválido"}
        
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
    except jwt.DecodeError: 
        resposta = {"message": "Token inválido."} 
        return False, resposta
    
#Função que retorna o username associado a certo token
def get_username(token):
    # Descodificar o token
    decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
    #Obter o username do utilizador
    username = decoded_token.get("username")
    return username

#Route para registar um aeroporto
@app.route('/sgdproj/airport', methods = ['POST'])
def cria_aeroporto():
    logger.info('POST /sgdproj/airport');   
    logger.info("---- Novo aeroporto  ----")
    payload = request.get_json()
    logger.debug(f'payload: {payload}')
    
    #Verificar o payload
    keysNeededAirport = ['nome', 'cidade', 'pais', 'id', 'token']
    response = verify_payload_keys(payload, keysNeededAirport)
    if response:
            return jsonify(response)
    
    admin_token = payload['token']
    
    conn = db_connection()
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_SERIALIZABLE)
    cur = conn.cursor()

    # Verify admin token
    is_admin, token_response = verify_admin_token(conn, admin_token)
    if not is_admin:
        response = {
            'status': StatusCodes['invalid_token'],
            'message': token_response['message']
        }
        return jsonify(response)
    
    statement = 'call addAeroporto (%s,%s,%s,%s,%s)'
    values = (payload['nome'], payload['cidade'], payload['pais'], payload['id'], get_username(admin_token))

    try:
        #Preencher os dados na tabela aeroporto
        cur.execute(statement, values)
        # Confirmar as transações
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

#Route para registar um voo
@app.route('/sgdproj/flight', methods = ['POST'])
def cria_voo():
    logger.info('POST /sgdproj/flight');   
    logger.info("---- Novo voo  ----")

    payload = request.get_json()

    logger.debug(f'payload: {payload}')
    
    # Verificar o payload
    keysNeededFlight = ['capacidade', 'id', 'aeroporto_origem', 'aeroporto_destino', 'token']
    response = verify_payload_keys(payload, keysNeededFlight)
    if response:
        return jsonify(response)
    
    conn = db_connection()
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_SERIALIZABLE)
    cur = conn.cursor()
    
    admin_token = payload['token']

    # Verificar admin token
    is_admin, token_response = verify_admin_token(conn, admin_token)
    if not is_admin:
        response = {
            'status': StatusCodes['invalid_token'],
            'message': token_response['message']
        }
        return jsonify(response)
    
    statement = ' call addVoo (%s, %s, %s, %s, %s)'
    values = (payload['capacidade'], payload['id'], get_username(admin_token), payload['aeroporto_origem'], payload['aeroporto_destino'])

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
        
#Route para registar um horário de um voo
@app.route('/sgdproj/schedule', methods = ['POST'])
def cria_horario():
    logger.info('POST /sgdproj/schedule');   
    logger.info("---- Novo horário  ----")

    payload = request.get_json()

    logger.debug(f'payload: {payload}')

    keysNeededSchedule = ['partida' ,'chegada','id','preco','voo_id', 'token']
    response=verify_payload_keys(payload, keysNeededSchedule)
    if response:
        return jsonify(response)
    
    conn = db_connection()
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_SERIALIZABLE)
    cur = conn.cursor()
    
    admin_token = payload['token']

    # Verificar admin token
    is_admin, token_response = verify_admin_token(conn, admin_token)
    if not is_admin:
        response = {
            'status': StatusCodes['invalid_token'],
            'message': token_response['message']
        }
        return jsonify(response)
    
    statement = ' call addhorario (%s,%s,%s,%s,%s, %s)'
    values = (payload['partida'], payload['chegada'], payload['id'],payload['preco'] ,payload['voo_id'], get_username(admin_token))

    try:
        #Preencher os dados na tabela horário
        cur.execute(statement, values)
        # Confirmae as transações
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
#Route para ver quais os horários de um voo
@app.route('/sgdproj/check_routes', methods = ['GET'])
def checkar_rotas():
    logger.info('GET /sgdproj/check_routes');   
    logger.info("---- Rotas Disponíveis  ----")

    payload = request.get_json()

    logger.debug(f'payload: {payload}')
    
    keysNeededRoutes = ['aeroporto_origem','aeroporto_destino', 'token']
    response= verify_payload_keys(payload, keysNeededRoutes)

    conn = db_connection()
    cur = conn.cursor()
    
    token = payload['token']

    # Verificar token
    is_user, token_response = verify_auth_token(conn, token)
    if not is_user:
        response = {
            'status': StatusCodes['invalid_token'],
            'message': token_response['message']
        }
        return jsonify(response)
       
    statement = ' SELECT * from check_rotas (%s,%s)'
    values = (payload['aeroporto_origem'], payload['aeroporto_destino'])

    try:
        #Preencher os dados na tabela horário
        cur.execute(statement, values)

        # Obter os resultados
        linhas = cur.fetchall()
        colunas = [desc[0] for desc in cur.description]  
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

# Route para verificar os lugares disponíveis num voo
@app.route('/sgdproj/check_seats', methods = ['GET'])
def checkar_lugar():
    logger.info('GET /sgdproj/check_seats  ');   
    logger.info("---- Lugares Disponíveis  ----")

    payload = request.get_json()
    
    logger.debug(f'payload: {payload}')

    keysNeededSeats = ['voo_id','horario_id','token']
    response = verify_payload_keys(payload, keysNeededSeats)
    if response:
        return jsonify(response)

    conn = db_connection()
    cur = conn.cursor()
    
    token = payload['token']

    # Verificar token
    is_user, token_response = verify_auth_token(conn, token)
    if not is_user:
        response = {
            'status': StatusCodes['invalid_token'],
            'message': token_response['message']
        }
        return jsonify(response)
    
    statement = ' SELECT * from check_seat (%s,%s)'
    values = (payload['voo_id'], payload['horario_id'])

    try:
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

#Route para reservar um voo
@app.route('/sgdproj/book_flight', methods=['POST'])
def compra():
    logger.info('POST /sgdproj/book_flight')
    logger.info("---- Reservar um voo ----")

    payload = request.get_json()
    
    logger.debug(f'payload: {payload}')

    # Verificar o payload
    keysNeededBook =  ['horario_id', 'seats','token']
    response = verify_payload_keys(payload, keysNeededBook)
    if response:
        return jsonify(response)
    
    token = payload['token']

    conn = db_connection()
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_SERIALIZABLE)
    cur = conn.cursor()
    
    # Verificar token
    is_client, token_response = verify_client_token(conn, token)
    if not is_client:
        response = {
            'status': StatusCodes['invalid_token'],
            'message': token_response['message']
        }
        return jsonify(response)
    
    keysNeededBook =  ['horario_id', 'seats','token']

    statement = 'call addCompra( %s, %s, %s)'
    values = (payload['horario_id'], get_username(payload['token']), payload['seats'])
    
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

# Route para obter os n destinos com mais voos no último ano
@app.route('/sgdproj/report/topDestinations/<int:n>', methods = ['GET'])
def n_destinos(n):
    logger.info('GET /sgdproj/report/topDestinations/<int:n>');   
    logger.info("---- Top destinos  ----")

    payload = request.get_json()
    
    logger.debug(f'payload: {payload}')
    
    # Verificar se o token existe no payload
    keyNeeded = ['token']
    response = verify_payload_keys(payload, keyNeeded)
    if response:
        return jsonify(response)
   
    conn = db_connection()
    cur = conn.cursor()
    
    token = payload['token']

    # Verificar token
    is_user, token_response = verify_auth_token(conn, token)
    if not is_user:
        response = {
            'status': StatusCodes['invalid_token'],
            'message': token_response['message']
        }
        return jsonify(response)
    statement = ' SELECT * from top_destinos (%s)'
    values = ((n,))

    try:
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

    keyNeeded = ['token']
    response = verify_payload_keys(payload, keyNeeded)
    if response:
        return jsonify(response)

    conn = db_connection()
    cur = conn.cursor()

    token = payload['token']

    # Verificar token
    is_user, token_response = verify_auth_token(conn, token)
    if not is_user:
        response = {
            'status': StatusCodes['invalid_token'],
            'message': token_response['message']
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

    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
