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
        # NOTE: change the host to "db" if you are running as a Docker container
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

# Function that verify user password
def verify_password(db_hash, provided_hash):
    provided_hash = hashlib.sha256(provided_hash.encode()).hexdigest()
    # Compare hashes
    return db_hash == provided_hash

#fazer uma para o início

#ESTE É O DO CLIENTE
@app.route('/sgdproj/register/client', methods = ['POST'])
def register_client():
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
            'status': StatusCodes['internal_error'],
            'message': str(error)
        }
    finally:
        if conn is not None:
            cur.close()
            conn.close()

    return jsonify(result)

# REGISTAR O  Admin
@app.route('/sgdproj/register/admin', methods = ['POST'])
def register_admin():
    logger.info('POST /sgdproj/register/admin');   
    payload = request.get_json()

    # Verificar se o token existe no payload
    if 'token' not in payload:
        response = {
            'status': StatusCodes['api_error'],
            'message': 'Token não existe'
        }
        return jsonify(response)
   
    conn = db_connection()
    cur = conn.cursor()

    logger.info("---- Novo  Admin  ----")
    logger.debug(f'payload: {payload}')


    # Admin token
    admin_token = payload['token']

    # Verify admin token
    if not verify_admin_token(cur, admin_token):
        response = {
            'status': StatusCodes['invalid_token'],
            'message': 'Admin token inválido'
        }
        return jsonify(response)
    
    # Check payload keys
    keysNeededAdmin = ['username', 'password', 'nome', 'genero', 'data_nascimento', 'telefone','email', 'funcao']
    for key in keysNeededAdmin:
        if key not in payload :
            response = {
                'status': StatusCodes ['api_error'],
                'message': f'{key} key not in admin payload' 
            }
        return jsonify(response)
    
    # Encrypt password
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
        result = {
            'status': StatusCodes['internal_error'],
            'message': str(error)
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
            'status': StatusCodes['internal_error'],
            'message': str(error)
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
        result = {
            'status': StatusCodes['internal_error'],
            'message': 'Internal error',
            'results':  f'Error: {error}'
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
    # Decode token
    decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
    # Extract data from token
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
    # Decode token
    decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
    # Extract data from token
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
    logger.debug(f'payload: {payload}')
    
    payload = request.get_json()
    
    # Verificar se o token existe no payload
    if 'token' not in payload:
        response = {
            'status': StatusCodes['api_error'],
            'message': 'Token não existe'
        }
        return jsonify(response)
   
    conn = db_connection()
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
        
    statement = ' call addAirport (%s;%s;%s;%s;%s)'
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
        result = {
            'status': StatusCodes['internal_error'],
            'message': str(error)
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
    logger.debug(f'payload: {payload}')
    
    payload = request.get_json()
    
    # Verificar se o token existe no payload
    if 'token' not in payload:
        response = {
            'status': StatusCodes['api_error'],
            'message': 'Token não existe'
        }
        return jsonify(response)
   
    conn = db_connection()
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
    
    keysNeededFlight = ['preco', 'capacidade', 'id', 'aeroporto_origem', 'aeroporto_destino']
    for key in keysNeededFlight:
        if key not in payload:
            response = {
                'status': StatusCodes['api_error'],
                'message': f'{key} value not in payload'
            }
            return jsonify(response)
    
    statement = ' call addFlight (%s;%s;%s;%s;%s,%s)'
    values = (payload['preco'], payload['capacidade'], payload['id'], admin_username(admin_token), payload['aeroporto_origem'], payload['aeroporto_destino'])

    try:
        #Preencher os dados na tabela voo
        cur.execute(statement, values)
        # Commitar as transações
        conn.commit()
        result = {
            'status': StatusCodes['success'],
            'message': 'Voo criado com sucesso',
            'results':  payload['id']
        }
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        conn.rollback()
        result = {
            'status': StatusCodes['internal_error'],
            'message': str(error)
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
    logger.debug(f'payload: {payload}')
    
    payload = request.get_json()
    
    # Verificar se o token existe no payload
    if 'token' not in payload:
        response = {
            'status': StatusCodes['api_error'],
            'message': 'Token não existe'
        }
        return jsonify(response)
   
    conn = db_connection()
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
    
    keysNeededSchedule = ['partida' ,'chegada','id',' voo_id','administrador_utilizador_username']
    for key in keysNeededSchedule:
        if key not in payload:
            response = {
                'status': StatusCodes['api_error'],
                'message': f'{key} value not in payload'
            }
            return jsonify(response)
    
    statement = ' call addSchedule (%s;%s;%s;%s;%s)'
    values = (payload['partida'], payload['chegada'], payload['id'], payload['voo_id'], admin_username(admin_token))

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
        result = {
            'status': StatusCodes['internal_error'],
            'message': str(error)
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
    logger.debug(f'payload: {payload}')
    
    payload = request.get_json()
    
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
       
    statement = ' SELECT * from check_rotas (%s;%s)'
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
        result = {
            'status': StatusCodes['internal_error'],
            'message': str(error)
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
    logger.debug(f'payload: {payload}')
    
    payload = request.get_json()
    
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
       
    statement = ' SELECT * from check_seat (%s;%s)'
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
        result = {
            'status': StatusCodes['internal_error'],
            'message': str(error)
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
    
    # Verificar token
    if not verify_auth_token(conn, token):
        response = {
            'status': StatusCodes['invalid_token'],
            'message': 'Token inválido'
        }
        return jsonify(response)
    
    keysNeededBook = ['partida' ,'chegada','id',' voo_id','administrador_utilizador_username']
    for key in keysNeededBook:
        if key not in payload:
            response = {
                'status': StatusCodes['api_error'],
                'message': f'{key} value not in payload'
            }
            return jsonify(response)
    try:
        # Conectar ao banco de dados
        conn = db_connection()
        cur = conn.cursor()

        # Configurar o nível de isolamento de transação para SERIALIZABLE
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_SERIALIZABLE)

        # Obter os parâmetros necessários do payload
        voo_id = payload['flight_code']
        horario_id = payload['schedule_id']
        seat_id = payload['seat_id']
        token = payload['token']

        # Chamar o procedimento armazenado para a compra
        cur.execute("""
            CALL book_flight(%s, %s, %s, %s);
        """, (voo_id, horario_id, seat_id, token))

        response = {
            'status': StatusCodes['success'],
            'results': {'schedule_id': horario_id}
        }

        # Commitar a transação
        conn.commit()

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        conn.rollback()  # Reverter a transação em caso de erro
        response = {
            'status': StatusCodes['internal_error'],
            'message': str(error)
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
    logger.debug(f'payload: {payload}')
    
    payload = request.get_json()
    
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
       
    statement = ' SELECT * from top_destinations (%s)'
    values = ((n,))

    try:
        #Preencher os dados na tabela horário
        cur.execute(statement, values)
        valores = cur.fetchall()  
        results = [
            {"destination_airport": row[0], "number_flights": row[1]} for row in results
        ]

        # Retornar a resposta com os dados
        result = {
            'status': StatusCodes['success'],
            'results' : results
        }
  
    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        result = {
            'status': StatusCodes['internal_error'],
            'message': str(error)
        }
    finally:
        if conn is not None:
            cur.close()
            conn.close()
    
    return jsonify(result)

@app.route('/sgdproj/report/topRoutes/<int:n>', methods=['GET'])
def top_routes(n):
    logger.info('GET /sgdproj/report/topRoutes/<int:n>')
    logger.info("---- Top routes ----")

    payload = request.get_json()

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
            'status': 401,
            'message': 'Token inválido'
        }
        return jsonify(response)

    statement = 'SELECT * FROM get_top_routes_last_12_months(%s);'
    values = (n,)

    try:
        cur.execute(statement, values)
        rows = cur.fetchall()

        # Estrutura para armazenar os resultados agrupados por mês
        results = {}
        for row in rows:
            month = row[0]
            flight_id = row[1]
            total_passengers = row[2]

            if month not in results:
                results[month] = []
            results[month].append({
                "flight_id": flight_id,
                "total_passengers": total_passengers
            })

        # Formatar a resposta para a API
        formatted_results = [
            {"month": month, "topN": flights} for month, flights in sorted(results.items())
        ]

        result = {
            'status': 200,
            'results': formatted_results
        }

    except (Exception, psycopg2.DatabaseError) as error:
        logger.error(error)
        result = {
            'status': 500,
            'message': str(error)
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
