##
## =============================================
## ======== Sistemas de Gestão de Dados =========
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
        if tipo_user ==1:
            role = 'client'
        elif tipo_user == 2:
            role = 'crew'
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
            resposta = {"message": "Admin verificado"} 
            return True, resposta
        else:
            resposta = {"message": "Token inválido"} 
            return False, resposta
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
            FROM cliente
            WHERE utilizador_username = %s;
            """
            cur.execute(query, (username,))
            client_data = cur.fetchone()
        
        if client_data:
            resposta = {"message": "Cliente verificado"} 
            return True, resposta
        else:
            resposta = {"message": "Token inválido"} 
            return False, resposta
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
        if role != 'client' and role != 'admin' and role != 'crew':
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
            resposta = {"message": "User verificado"} 
            return True, resposta
        else:
            resposta = {"message": "Token inválido"} 
            return False, resposta
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
    
    keysNeededRoutes = ['token']
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
    values = (payload.get('aeroporto_origem'), payload.get('aeroporto_destino'))

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

    statement = 'SELECT addCompra(%s, %s, %s)'
    values = (payload['horario_id'], get_username(payload['token']), payload['seats'])
    
    try:
        cur.execute(statement, values)
        compra_id = cur.fetchone()[0]

        response = {
            'status': StatusCodes['success'],
            'results': {'schedule_id': payload['horario_id'], 'id de compra': compra_id}
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

@app.route('/sgdproj/bilhetes', methods = ['GET'])
def consulta_bilhete():
    logger.info('GET /sgdproj/bilhetes');   
    logger.info("---- Consultar bilhetes  ----")

    payload = request.get_json()
    
    logger.debug(f'payload: {payload}')
    
    # Verificar o payload
    keyNeeded = ['compra_id','token']
    response = verify_payload_keys(payload, keyNeeded)
    if response:
        return jsonify(response)
    
    conn = db_connection()
    cur = conn.cursor()

    token = payload['token']

    # Verificar token
    is_client, token_response = verify_client_token(conn, token)
    if not is_client:
        response = {
            'status': StatusCodes['invalid_token'],
            'message': token_response['message']
        }
        return jsonify(response)

    statment = "SELECT * FROM bilhetes(%s);"
    values = (payload ['compra_id'],)
    
    try:
        cur.execute(statment, values)
        bilhetes = cur.fetchall()
        
        if not bilhetes:
            return {"message": "Nenhum bilhete encontrado para esse id_compra."}

        resultado = []
        for i, bilhete in enumerate(bilhetes):
            resultado.append({
                f'bilhete {i + 1}': {
                    'nome': bilhete[0],
                    'id': bilhete[1],
                    'compra_id': bilhete[2],
                    'assento_id': bilhete[3],
                    'assento_horario_id': bilhete[4]
                }
            })
        
        # Retornar a resposta com os dados
        result = {
            'status': StatusCodes['success'],
            'results' : resultado
        }
  
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return {"message": "Erro ao procurar bilhetes."}
    
    finally:
        if conn is not None:
            cur.close()
            conn.close()
    
    return jsonify(result)

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
    
        results = []
        for ano, mes, voo_id, num_bilhetes in tabela:
            mes_data = next((item for item in results if item["ano"] == ano and item["mês"] == mes), None)
            if mes_data is None:
                mes_data = {"ano": ano, "mês": mes, "TopN": []}
                results.append(mes_data)
            mes_data["TopN"].append({"id_voo": voo_id,"total_passageiros": num_bilhetes})

        #retornar a resposta com os dados
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

@app.route('/sgdproj/assento', methods=['POST'])
def cria_assento():
    logger.info('POST /sgdproj/assento')
    logger.info("---- Novos asentos ----")

    payload = request.get_json()

    logger.debug(f'payload: {payload}')

    keyNeeded = ['seats','token']
    response = verify_payload_keys(payload, keyNeeded)
    if response:
        return jsonify(response)

    conn = db_connection()
    cur = conn.cursor()

    token = payload['token']

    # Verificar token
    is_admin, token_response = verify_admin_token(conn, token)
    if not is_admin:
        response = {
            'status': StatusCodes['invalid_token'],
            'message': token_response['message']
        }
        return jsonify(response)
    
    statement = 'call addAssentos(%s)'
    values = (payload['seats'],)
    
    try:
        cur.execute(statement, values)

        # Retornar a resposta com os dados
        response = {
            'status': StatusCodes['success'],
            'message': 'Assentos não repetidos adicionados com sucesso'}

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

@app.route('/sgdproj/payment', methods=['POST'])
def efetuar_pagamento():
    logger.info('POST /sgdproj/payment')
    logger.info("---- Efetuar Pagamento ----")

    payload = request.get_json()
    logger.debug(f'payload: {payload}')

    # Verificar os campos necessários
    keysNeededPayment = ['compra_id', 'metodos_pagamento', 'token']
    response = verify_payload_keys(payload, keysNeededPayment)
    if response:
        return jsonify(response)

    conn = db_connection()
    # Configurar o nível de isolamento como SERIALIZABLE para evitar condições de corrida
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_SERIALIZABLE)
    cur = conn.cursor()

    token = payload['token']

    # Verificar token
    is_client, token_response = verify_client_token(conn, token)
    if not is_client:
        response = {
            'status': StatusCodes['invalid_token'],
            'message': token_response['message']
        }
        return jsonify(response)

    try:
        # Recuperar o valor total da compra e bloquear a linha da compra
        cur.execute("SELECT valor FROM compra WHERE id = %s FOR UPDATE;", (payload['compra_id'],))
        compra = cur.fetchone()
        if not compra:
            raise ValueError('Compra não encontrada.')

        valor_total_compra = compra[0]

        # Verificar se a compra já foi paga
        cur.execute("SELECT COUNT(*) FROM pagamento WHERE compra_id = %s;", (payload['compra_id'],))
        pagamentos_existentes = cur.fetchone()[0]

        if pagamentos_existentes > 0:
            return jsonify({
                'status': StatusCodes['api_error'],
                'message': 'Pagamento já realizado para esta compra. Pagamentos duplicados não são permitidos.'
            })

        # Calcular o valor total dos pagamentos
        metodos_pagamento = payload['metodos_pagamento']
        valor_total_pagamento = sum(metodo['valor'] for metodo in metodos_pagamento)

        # Validar se o total pago corresponde ao valor da compra
        if valor_total_pagamento != valor_total_compra:
            return jsonify({
                'status': StatusCodes['api_error'],
                'message': f'O valor total do pagamento ({valor_total_pagamento}) não corresponde ao valor da compra ({valor_total_compra}).'
            })

        # Processar cada método de pagamento
        for metodo in metodos_pagamento:
            # Validar informações do método individual
            if not all(k in metodo for k in ('metodo_pagamento', 'detalhes', 'valor')):
                raise ValueError('Cada método de pagamento deve conter "metodo_pagamento", "detalhes" e "valor".')

            metodo_tipo = metodo['metodo_pagamento'].upper()
            detalhes = metodo['detalhes']
            valor = metodo['valor']

            # Inserir pagamento principal
            pagamento_statement = '''
                INSERT INTO pagamento (data, valor, estado, compra_id)
                VALUES (NOW(), %s, 'Concluído', %s) RETURNING id;
            '''
            cur.execute(pagamento_statement, (valor, payload['compra_id']))
            pagamento_id = cur.fetchone()[0]

            # Inserir detalhes do método
            if metodo_tipo == 'MBWAY':
                mbway_statement = '''
                    INSERT INTO pagamento_mbway (id, telefone, valor, pagamento_id)
                    VALUES (DEFAULT, %s, %s, %s);
                '''
                cur.execute(mbway_statement, (detalhes['telefone'], valor, pagamento_id))
            elif metodo_tipo == 'CREDITO':
                credito_statement = '''
                    INSERT INTO pagamento_credito (id, valor, n_conta, pagamento_id)
                    VALUES (DEFAULT, %s, %s, %s);
                '''
                cur.execute(credito_statement, (valor, detalhes['n_conta'], pagamento_id))
            elif metodo_tipo == 'DEBITO':
                debito_statement = '''
                    INSERT INTO pagamento_debito (id, valor, n_conta, pagamento_id)
                    VALUES (DEFAULT, %s, %s, %s);
                '''
                cur.execute(debito_statement, (valor, detalhes['n_conta'], pagamento_id))
            else:
                raise ValueError(f'Método de pagamento "{metodo_tipo}" inválido.')

        conn.commit()
        response = {
            'status': StatusCodes['success'],
            'message': 'Pagamentos efetuados com sucesso',
            'results': {'compra_id': payload['compra_id']}
        }

    except psycopg2.errors.SerializationFailure as error:
        logger.error(error)
        conn.rollback()
        response = {
            'status': StatusCodes['api_error'],
            'message': 'Conflito detectado. Tente novamente.'
        }

    except Exception as error:
        logger.error(error)
        conn.rollback()
        response = {
            'status': StatusCodes['internal_error'],
            'message': f'Erro ao processar pagamento: {error}'
        }

    finally:
        if conn is not None:
            cur.close()
            conn.close()

    return jsonify(response)

@app.route('/sgdproj/report/financial_data', methods=['GET'])
def relatorio_financeiro():
    logger.info('GET /sgdproj/report/financial_data')
    logger.info("---- Relatório Financeiro ----")

    payload = request.get_json()
    logger.debug(f'payload: {payload}')

    # Verificar se o token existe
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

    # Consultar dados financeiros
    financeiro_statement = '''
        SELECT
            v.id AS flight_code,
            COALESCE(SUM(pc.valor), 0) AS credit_card,
            COALESCE(SUM(pd.valor), 0) AS debt_card,
            COALESCE(SUM(pm.valor), 0) AS mbway,
            COALESCE(SUM(pc.valor), 0) + COALESCE(SUM(pd.valor), 0) + COALESCE(SUM(pm.valor), 0) AS total
        FROM
            voo v
        LEFT JOIN horario h ON v.id = h.voo_id
        LEFT JOIN compra c ON h.id = c.horario_id
        LEFT JOIN pagamento p ON c.id = p.compra_id
        LEFT JOIN pagamento_credito pc ON p.id = pc.pagamento_id
        LEFT JOIN pagamento_debito pd ON p.id = pd.pagamento_id
        LEFT JOIN pagamento_mbway pm ON p.id = pm.pagamento_id
        WHERE
            p.data >= NOW() - INTERVAL '12 months'
        GROUP BY v.id
        ORDER BY total DESC;
    '''

    try:
        cur.execute(financeiro_statement)
        rows = cur.fetchall()
        results = [
            {
                "flight_code": row[0],
                "credit_card": row[1],
                "debt_card": row[2],
                "mbway": row[3],
                "total": row[4]
            } for row in rows
        ]

        response = {
            'status': StatusCodes['success'],
            'results': results
        }

    except Exception as error:
        logger.error(error)
        response = {
            'status': StatusCodes['internal_error'],
            'message': f'Erro ao gerar relatório financeiro: {error}'
        }

    finally:
        if conn is not None:
            cur.close()
            conn.close()

    return jsonify(response)



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
