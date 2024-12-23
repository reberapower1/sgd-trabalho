/* 
	# 
	# Sistemas de Gestão de Dados 2024/2025
	# Trabalho Prático - DEIJet
	#
*/
CREATE TABLE cliente (
	utilizador_username VARCHAR(512) NOT NULL,
	PRIMARY KEY(utilizador_username)
);

CREATE TABLE utilizador (
	username	 VARCHAR(512) NOT NULL,
	password	 VARCHAR(512) NOT NULL,
	nome		 VARCHAR(512) NOT NULL,
	genero		 VARCHAR(512) NOT NULL,
	data_nascimento DATE NOT NULL,
	telefone	 INTEGER NOT NULL,
	email		 VARCHAR(512) NOT NULL,
	PRIMARY KEY(username)
);

CREATE TABLE tripulante (
	funcao		 VARCHAR(512) NOT NULL,
	utilizador_username VARCHAR(512) NOT NULL,
	PRIMARY KEY(utilizador_username)
);

CREATE TABLE administrador (
	funcao				 VARCHAR(512) NOT NULL,
	utilizador_username		 VARCHAR(512) NOT NULL,
	PRIMARY KEY(utilizador_username)
);

CREATE TABLE compra (
	id				 BIGSERIAL,
	data			 TIMESTAMP NOT NULL,
	valor			 FLOAT(8) NOT NULL,
	horario_id			 INTEGER NOT NULL,
	cliente_utilizador_username VARCHAR(512) NOT NULL,
	PRIMARY KEY(id)
);

CREATE TABLE voo (
	capacidade			 INTEGER NOT NULL,
	id				 INTEGER,
	administrador_utilizador_username VARCHAR(512) NOT NULL,
	aeroporto_origem			 INTEGER NOT NULL,
	aeroporto_destino			 INTEGER NOT NULL,
	PRIMARY KEY(id)
);

CREATE TABLE pagamento (
	id	 BIGSERIAL,
	data	 TIMESTAMP NOT NULL,
	valor	 FLOAT(8) NOT NULL,
	estado	 VARCHAR(512) NOT NULL,
	compra_id BIGINT NOT NULL,
	PRIMARY KEY(id)
);

CREATE TABLE pagamento_mbway (
	id		 BIGSERIAL,
	telefone	 INTEGER NOT NULL,
	valor	 FLOAT(8) NOT NULL,
	pagamento_id BIGINT,
	PRIMARY KEY(id,pagamento_id)
);

CREATE TABLE pagamento_credito (
	id		 BIGSERIAL,
	valor	 FLOAT(8) NOT NULL,
	n_conta	 BIGINT NOT NULL,
	pagamento_id BIGINT,
	PRIMARY KEY(id,pagamento_id)
);

CREATE TABLE pagamento_debito (
	n_conta	 BIGINT NOT NULL,
	valor	 FLOAT(8) NOT NULL,
	id		 BIGSERIAL NOT NULL,
	pagamento_id BIGINT,
	PRIMARY KEY(id,pagamento_id)
);

CREATE TABLE horario (
	partida				 TIMESTAMP NOT NULL,
	chegada				 TIMESTAMP NOT NULL,
	id				 INTEGER,
	preco				 FLOAT(8),
	voo_id				 INTEGER NOT NULL,
	administrador_utilizador_username VARCHAR(512) NOT NULL,
	PRIMARY KEY(id)
);

CREATE TABLE aeroporto (
	nome				 VARCHAR(512) NOT NULL,
	cidade				 VARCHAR(512) NOT NULL,
	pais				 VARCHAR(512) NOT NULL,
	id				 INTEGER,
	administrador_utilizador_username VARCHAR(512) NOT NULL,
	PRIMARY KEY(id)
);

CREATE TABLE bilhete (
	nome		 VARCHAR(512),
	id		 BIGINT,
	compra_id		 BIGINT,
	assento_id	 VARCHAR(512) NOT NULL,
	assento_horario_id INTEGER NOT NULL,
	PRIMARY KEY(id,compra_id)
);

CREATE TABLE assento (
	id		 VARCHAR(512) NOT NULL,
	localizacao	 BOOL NOT NULL,
	disponibilidade BOOL NOT NULL,
	horario_id	 INTEGER,
	PRIMARY KEY(id,horario_id)
);

CREATE TABLE tripulante_horario (
	tripulante_utilizador_username VARCHAR(512),
	horario_id			 INTEGER,
	PRIMARY KEY(tripulante_utilizador_username,horario_id)
);

CREATE TABLE tripulante_tripulante (
	tripulante_utilizador_username	 VARCHAR(512),
	tripulante_utilizador_username1 VARCHAR(512) NOT NULL,
	PRIMARY KEY(tripulante_utilizador_username)
);

CREATE TABLE administrador_administrador (
	administrador_utilizador_username	 VARCHAR(512),
	administrador_utilizador_username1 VARCHAR(512) NOT NULL,
	PRIMARY KEY(administrador_utilizador_username)
);

ALTER TABLE cliente ADD CONSTRAINT cliente_fk1 FOREIGN KEY (utilizador_username) REFERENCES utilizador(username);
ALTER TABLE tripulante ADD CONSTRAINT tripulante_fk1 FOREIGN KEY (utilizador_username) REFERENCES utilizador(username);
ALTER TABLE administrador ADD CONSTRAINT administrador_fk2 FOREIGN KEY (utilizador_username) REFERENCES utilizador(username);
ALTER TABLE compra ADD CONSTRAINT compra_fk1 FOREIGN KEY (horario_id) REFERENCES horario(id);
ALTER TABLE compra ADD CONSTRAINT compra_fk2 FOREIGN KEY (cliente_utilizador_username) REFERENCES cliente(utilizador_username);
ALTER TABLE voo ADD CONSTRAINT voo_fk1 FOREIGN KEY (administrador_utilizador_username) REFERENCES administrador(utilizador_username);
ALTER TABLE voo ADD CONSTRAINT voo_fk2 FOREIGN KEY (aeroporto_origem) REFERENCES aeroporto(id);
ALTER TABLE voo ADD CONSTRAINT voo_fk3 FOREIGN KEY (aeroporto_destino) REFERENCES aeroporto(id);
ALTER TABLE pagamento ADD CONSTRAINT pagamento_fk1 FOREIGN KEY (compra_id) REFERENCES compra(id);
ALTER TABLE pagamento_mbway ADD CONSTRAINT pagamento_mbway_fk1 FOREIGN KEY (pagamento_id) REFERENCES pagamento(id);
ALTER TABLE pagamento_credito ADD CONSTRAINT pagamento_credito_fk1 FOREIGN KEY (pagamento_id) REFERENCES pagamento(id);
ALTER TABLE pagamento_debito ADD CONSTRAINT pagamento_debito_fk1 FOREIGN KEY (pagamento_id) REFERENCES pagamento(id);
ALTER TABLE horario ADD CONSTRAINT horario_fk1 FOREIGN KEY (voo_id) REFERENCES voo(id);
ALTER TABLE horario ADD CONSTRAINT horario_fk2 FOREIGN KEY (administrador_utilizador_username) REFERENCES administrador(utilizador_username);
ALTER TABLE aeroporto ADD CONSTRAINT aeroporto_fk1 FOREIGN KEY (administrador_utilizador_username) REFERENCES administrador(utilizador_username);
ALTER TABLE bilhete ADD UNIQUE (id, assento_id, assento_horario_id);
ALTER TABLE bilhete ADD CONSTRAINT bilhete_fk1 FOREIGN KEY (compra_id) REFERENCES compra(id);
ALTER TABLE bilhete ADD CONSTRAINT bilhete_fk2 FOREIGN KEY (assento_id, assento_horario_id) REFERENCES assento(id, horario_id);
ALTER TABLE assento ADD CONSTRAINT assento_fk1 FOREIGN KEY (horario_id) REFERENCES horario(id);
ALTER TABLE tripulante_horario ADD CONSTRAINT tripulante_horario_fk1 FOREIGN KEY (tripulante_utilizador_username) REFERENCES tripulante(utilizador_username);
ALTER TABLE tripulante_horario ADD CONSTRAINT tripulante_horario_fk2 FOREIGN KEY (horario_id) REFERENCES horario(id);
ALTER TABLE tripulante_tripulante ADD CONSTRAINT tripulante_tripulante_fk1 FOREIGN KEY (tripulante_utilizador_username) REFERENCES tripulante(utilizador_username);
ALTER TABLE tripulante_tripulante ADD CONSTRAINT tripulante_tripulante_fk2 FOREIGN KEY (tripulante_utilizador_username1) REFERENCES tripulante(utilizador_username);
ALTER TABLE administrador_administrador ADD CONSTRAINT administrador_administrador_fk1 FOREIGN KEY (administrador_utilizador_username) REFERENCES administrador(utilizador_username);
ALTER TABLE administrador_administrador ADD CONSTRAINT administrador_administrador_fk2 FOREIGN KEY (administrador_utilizador_username1) REFERENCES administrador(utilizador_username);

CREATE OR REPLACE PROCEDURE addUtilizador(
    username     utilizador.username%type,
    password  utilizador.password%type,
    nome        utilizador.nome%type,
    genero      utilizador.genero%type,
    data_nascimento utilizador.data_nascimento%type,
    telefone    utilizador.telefone%type,
    email       utilizador.email%type
)
LANGUAGE plpgsql
AS $$
BEGIN
    -- Bloquear a tabela utilizador
    LOCK TABLE utilizador IN EXCLUSIVE MODE;
    -- Inserir os dados na tabela utilizador
    INSERT INTO utilizador (username, password, nome, genero, data_nascimento, telefone, email)
    VALUES (username, password, nome, genero, data_nascimento, telefone, email);

EXCEPTION
    WHEN unique_violation THEN
        RAISE EXCEPTION 'Erro: O username já existe.';
    WHEN others THEN
        RAISE EXCEPTION 'Erro inesperado: %', SQLERRM;
END;
$$;

CREATE OR REPLACE PROCEDURE addClient( username utilizador.username%type,
    password  utilizador.password%type,
    nome        utilizador.nome%type,
    genero      utilizador.genero%type,
    data_nascimento utilizador.data_nascimento%type,
    telefone    utilizador.telefone%type,
    email       utilizador.email%type)
LANGUAGE plpgsql
AS $$
BEGIN
	call addUtilizador(username, password, nome, genero, data_nascimento, telefone, email);
	INSERT INTO cliente (utilizador_username)
	VALUES (username);
EXCEPTION
    WHEN foreign_key_violation THEN
        RAISE EXCEPTION 'Erro: O username não existe na tabela utilizador.';
    WHEN unique_violation THEN
        RAISE EXCEPTION 'Erro: O cliente já está registrado.';
    WHEN others THEN
        RAISE EXCEPTION 'Erro inesperado: %', SQLERRM;
END;
$$;

CREATE OR REPLACE PROCEDURE addAdmin(username utilizador.username%type,
    password  utilizador.password%type,
    nome        utilizador.nome%type,
    genero      utilizador.genero%type,
    data_nascimento utilizador.data_nascimento%type,
    telefone    utilizador.telefone%type,
    email       utilizador.email%type,
	funcao		administrador.funcao%type,
	administrador_utilizador_username administrador_administrador.administrador_utilizador_username%type
	)
LANGUAGE plpgsql
AS $$
BEGIN
    -- adicionar na tabela do utilizador
	call addUtilizador(username, password, nome, genero, data_nascimento, telefone, email);
    -- adicionar na do administrador
	INSERT INTO administrador(utilizador_username, funcao)
	VALUES (username, funcao);
    --adicionar na dos criadores/criados por
    INSERT INTO administrador_administrador(administrador_utilizador_username, administrador_utilizador_username1 )
    VALUES (username, administrador_utilizador_username);
EXCEPTION
    WHEN foreign_key_violation THEN
        RAISE EXCEPTION 'Erro: O username não existe na tabela utilizador.';
    WHEN unique_violation THEN
        RAISE EXCEPTION 'Erro: O administrador já está registado.';
    WHEN others THEN
        RAISE EXCEPTION 'Erro inesperado: %', SQLERRM;
END;
$$;

CREATE OR REPLACE PROCEDURE addCrew( username utilizador.username%type,
    password  utilizador.password%type,
    nome        utilizador.nome%type,
    genero      utilizador.genero%type,
    data_nascimento utilizador.data_nascimento%type,
    telefone    utilizador.telefone%type,
    email       utilizador.email%type,
	funcao		tripulante.funcao%type
	)
LANGUAGE plpgsql
AS $$
BEGIN
	call addUtilizador(username, password, nome, genero, data_nascimento, telefone, email);
	INSERT INTO tripulante(utilizador_username, funcao)
	VALUES (username, funcao);
EXCEPTION
    WHEN unique_violation THEN
        RAISE EXCEPTION 'O username já existe.';

    -- Quando a FK não é válida
    WHEN foreign_key_violation THEN
        RAISE EXCEPTION 'Erro: O username não existe na tabela utilizador.';

    -- Qualquer outro erro
    WHEN others THEN
        RAISE EXCEPTION '%', SQLERRM;
END;
$$;

CREATE OR REPLACE FUNCTION login(username_login utilizador.username%type, password_login utilizador.password%type)
RETURNS integer AS $$
DECLARE
    tipo_user integer; verificar_user utilizador.username%type;
BEGIN

	-- Verificar se o utilizador está registado
    IF NOT EXISTS (
        SELECT 1
        FROM utilizador
        WHERE utilizador.username = username_login
    ) THEN
        RAISE EXCEPTION 'Utilizador não registado';
    END IF;

    -- Verificar se a password está correta
    IF NOT EXISTS (
        SELECT 1
        FROM utilizador
        WHERE utilizador.username = username_login AND utilizador.password = password_login
    ) THEN
        RAISE EXCEPTION 'Username ou password errados';
    END IF;

	-- Verificar o tipo de utilizador (cliente, tripulante ou administrador)
	SELECT 
        CASE
            WHEN EXISTS (SELECT 1 FROM cliente WHERE cliente.utilizador_username = username_login) THEN 1  -- cliente
            WHEN EXISTS (SELECT 1 FROM tripulante WHERE tripulante.utilizador_username = username_login) THEN 2  -- tripulante
            WHEN EXISTS (SELECT 1 FROM administrador WHERE administrador.utilizador_username = username_login) THEN 3  -- administrador
            ELSE NULL
        END
    INTO tipo_user;

    -- Se o username não for encontrado nas três tabelas, levanta-se a exceção
    IF tipo_user IS NULL THEN
        RAISE EXCEPTION 'Tipo de utilizador não encontrado';
    END IF;

    RETURN tipo_user;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE addAeroporto(
	nome aeroporto.nome%type,
	cidade aeroporto.cidade%type,				 
	pais aeroporto.pais%type,				 
	id aeroporto.id%type,	
	criador aeroporto.administrador_utilizador_username%type
)
LANGUAGE plpgsql
AS $$
BEGIN
    LOCK TABLE aeroporto IN EXCLUSIVE MODE;
    -- Insere os dados na tabela utilizador
    INSERT INTO aeroporto (nome, cidade, pais, id, administrador_utilizador_username)
    VALUES (nome, cidade, pais, id, criador);


EXCEPTION
	WHEN unique_violation THEN
        RAISE EXCEPTION 'O aeroporto com ID % já existe.', id;
    WHEN others THEN
        RAISE EXCEPTION 'Erro inesperado: %', SQLERRM;
END;
$$;

CREATE OR REPLACE PROCEDURE addVoo(
	capacidade voo.capacidade%type,
	id voo.id%type,
	administrador_utilizador_username voo.administrador_utilizador_username%type,
	aeroporto_origem voo.aeroporto_origem%type,
	aeroporto_destino voo.aeroporto_destino%type
)
LANGUAGE plpgsql
AS $$
BEGIN
    LOCK TABLE voo IN EXCLUSIVE MODE;
    -- Insere os dados na tabela utilizador
    INSERT INTO voo (capacidade, id, administrador_utilizador_username, aeroporto_origem, aeroporto_destino)
    VALUES (capacidade, id, administrador_utilizador_username, aeroporto_origem, aeroporto_destino);

EXCEPTION
	WHEN unique_violation THEN
        RAISE EXCEPTION 'O voo com ID % já existe.', id;
    WHEN others THEN
        RAISE EXCEPTION 'Erro inesperado: %', SQLERRM;
END;
$$;

CREATE OR REPLACE PROCEDURE addHorario(
	partida horario.partida%type,
	chegada horario.chegada%type,
	id horario.id%type,
    preco horario.preco%type,
	voo_id horario.voo_id%type,
	administrador_utilizador_username horario.administrador_utilizador_username%type 
)
LANGUAGE plpgsql
AS $$
BEGIN
    LOCK TABLE horario IN EXCLUSIVE MODE;
    -- Insere os dados na tabela utilizador
    INSERT INTO horario (partida,chegada,id, preco, voo_id, administrador_utilizador_username)
    VALUES (partida,chegada,id, preco, voo_id, administrador_utilizador_username);

EXCEPTION
	WHEN unique_violation THEN
        RAISE EXCEPTION 'O horário com ID % já existe.', id;
    WHEN others THEN
        RAISE EXCEPTION 'Erro inesperado: %', SQLERRM;
END;
$$;

CREATE OR REPLACE FUNCTION verificar_horario()
RETURNS TRIGGER AS $$
BEGIN
    -- Verificar se já existe um horário do voo no mesmo dia
    IF EXISTS (
        SELECT 1
        FROM horario
        WHERE voo_id = NEW.voo_id
          AND DATE(partida) = DATE(NEW.partida)
    ) THEN
        RAISE EXCEPTION 'O voo % já possui um horário para o dia: %.', NEW.voo_id, DATE(NEW.partida);
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER horario_trigger
BEFORE INSERT OR UPDATE ON horario
FOR EACH ROW
EXECUTE FUNCTION verificar_horario();

CREATE OR REPLACE FUNCTION check_rotas(
	origem_check voo.aeroporto_origem%type DEFAULT NULL, 
	destino_check voo.aeroporto_destino%type DEFAULT NULL
)
RETURNS TABLE (
    id_voo voo.id%type,
    id_horario horario.id%type,
    aeroporto_origem voo.aeroporto_origem%type,
    aeroporto_destino voo.aeroporto_destino%type 
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        voo.id,
        horario.id,
        voo.aeroporto_origem,
        voo.aeroporto_destino
    FROM 
        voo 
    JOIN 
        horario ON voo.id = horario.voo_id
    WHERE 
        (origem_check IS NULL OR voo.aeroporto_origem = origem_check)
        AND (destino_check IS NULL OR voo.aeroporto_destino = destino_check);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION check_seat(
    voo_id_check voo.id%type,
    horario_id_check horario.id%type
)
RETURNS VARCHAR [] AS $$
BEGIN
    RETURN ARRAY (
        SELECT assento.id
        FROM assento
        JOIN horario ON assento.horario_id = horario.id
        JOIN voo ON horario.voo_id = voo.id
		WHERE voo_id_check = voo.id and horario_id_check = horario.id and disponibilidade = true
    );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION verificar_disponibilidade_assento(
    id_check assento.id%type,
    horario_check horario.id%type
)
RETURNS BOOLEAN AS $$
DECLARE
    disponibilidade BOOLEAN;
BEGIN
    SELECT assento.disponibilidade INTO disponibilidade
    FROM assento
    WHERE assento.id = id_check AND assento.horario_id = horario_check
    FOR UPDATE;

    IF disponibilidade IS NULL THEN
        RAISE EXCEPTION 'Assento % não encontrado no horário %.', id_check, horario_check;
    END IF;

    RETURN disponibilidade;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION addCompra(
    horario_check horario.id%type,
    cliente_username utilizador.username%type,
    assentos_array VARCHAR[][]
)
RETURNS compra.id%type
LANGUAGE plpgsql AS $$
DECLARE
    preco_horario horario.preco%type;
    total_preco horario.preco%type;
    compra_id compra.id%type;
    disponibilidade assento.disponibilidade%type;
    nome_bilhete bilhete.nome%type;
    id_passageiro bilhete.id%type;
    assento_id assento.id%type;
BEGIN
    -- Verificar o preço do horário
    SELECT preco INTO preco_horario
    FROM horario
    WHERE horario.id = horario_check;

    IF preco_horario IS NULL THEN
        RAISE EXCEPTION 'Horário % não encontrado.', horario_check;
    END IF;

    -- Calcular o preço total da compra
    total_preco := array_length(assentos_array, 1) * preco_horario;

    -- Inserir os dados da compra na tabela compra
    INSERT INTO compra (data, valor, horario_id, cliente_utilizador_username)
    VALUES (NOW(), total_preco, horario_check, cliente_username)
    RETURNING id INTO compra_id;

    -- Iterar pelo array 
    FOR i IN 1..array_length(assentos_array, 1) LOOP
        -- ietrar por cada array, dentro do array
        nome_bilhete := assentos_array[i][1];
        id_passageiro := assentos_array[i][2]::INT;
        assento_id := assentos_array[i][3];

        -- Verificar a disponibilidade do assento
        disponibilidade := verificar_disponibilidade_assento(assento_id, horario_check);

        IF NOT disponibilidade THEN
            RAISE EXCEPTION 'Assento % não está disponível.', assento_id;
        END IF;

        -- Atualizar a disponibilidade dos assentos comprados
        UPDATE assento
        SET disponibilidade = false
        WHERE assento.id = assento_id AND horario_id = horario_check;

        -- Inserir os dados dos passageiros e compra na tabela bilhete
        INSERT INTO bilhete (nome, id, compra_id, assento_id, assento_horario_id)
        VALUES (nome_bilhete, id_passageiro, compra_id, assento_id, horario_check);
    END LOOP;
    RETURN compra_id;
END;
$$;


CREATE OR REPLACE FUNCTION top_destinos(n INTEGER)
RETURNS TABLE (
    aeroporto_destino aeroporto.id%type,
    n_voos BIGINT
) 
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        voo.aeroporto_destino AS aeroporto_destino,
        COUNT(horario.id) AS n_voos
    FROM 
        voo
    JOIN 
        horario ON voo.id = horario.voo_id
    WHERE 
        horario.partida >= date_trunc('month', CURRENT_DATE) - interval '12 months'
    GROUP BY 
        voo.aeroporto_destino
    ORDER BY 
        n_voos DESC
    LIMIT 
        n;
END;
$$;

CREATE OR REPLACE FUNCTION bilhetes(
    compra_id_check bilhete.compra_id%type
)
RETURNS TABLE (
    nome bilhete.nome%type,
    id bilhete.id%type,
    compra_id bilhete.compra_id%type,
    assento_id bilhete.assento_id%type,
    assento_horario_id bilhete.assento_horario_id%type
) AS $$
BEGIN
    RETURN QUERY
    SELECT bilhete.nome, bilhete.id, bilhete.compra_id, bilhete.assento_id, bilhete.assento_horario_id
    FROM bilhete
    WHERE bilhete.compra_id = compra_id_check;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION top_rotas(n INTEGER)
RETURNS TABLE(
    ano INTEGER,
    mes_numero INTEGER,
    voo_id INTEGER,
    num_bilhetes INTEGER
) AS $$
BEGIN
    RETURN QUERY
    WITH meses AS (
        SELECT generate_series(date_trunc('month', NOW() - INTERVAL '12 months'),
        date_trunc('month', NOW() - INTERVAL '1 month'),'1 month')::
        DATE AS mes
    ),
    voos AS (
        SELECT
            horario.voo_id,
            horario.partida,
            COUNT(bilhete.id)::INTEGER AS total_bilhetes
        FROM
            horario
        LEFT JOIN bilhete ON horario.id = bilhete.assento_horario_id
        GROUP BY
            horario.voo_id, horario.partida
    ),
    ranked_voos AS (
        SELECT
            extract(year from meses.mes)::INTEGER AS ano,
            extract(month from meses.mes)::INTEGER AS mes_numero,
            voos.voo_id,
            voos.total_bilhetes AS bilhetes_por_voo,
            ROW_NUMBER() OVER (PARTITION BY extract(year from meses.mes), extract(month from meses.mes) ORDER BY voos.total_bilhetes DESC) AS rn
        FROM
            meses
        LEFT JOIN voos ON voos.partida >= meses.mes AND voos.partida < (meses.mes + INTERVAL '1 month')
    )
    SELECT
        ranked_voos.ano,    
        ranked_voos.mes_numero,
        ranked_voos.voo_id,
        ranked_voos.bilhetes_por_voo
    FROM
        ranked_voos
    WHERE
        ranked_voos.rn <= n
    ORDER BY
        ranked_voos.ano,ranked_voos.mes_numero, ranked_voos.bilhetes_por_voo DESC;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE PROCEDURE addAssentos(
    assentos_array VARCHAR[][]
)
LANGUAGE plpgsql AS $$
DECLARE
    id_insere		 assento.id%type;
	localizacao_insere assento.localizacao%type;
	horario_id_insere	 assento.horario_id%type;
BEGIN
    -- Iterar pelo array 
    FOR i IN 1..array_length(assentos_array, 1) LOOP
        -- iterar por cada array, dentro do array
        id_insere := assentos_array[i][1];
        localizacao_insere := assentos_array[i][2];
        horario_id_insere := assentos_array[i][3]::INTEGER;

        LOCK TABLE assento IN EXCLUSIVE MODE;
        INSERT INTO assento (id, localizacao, disponibilidade,horario_id)
        VALUES (id_insere, localizacao_insere,true , horario_id_insere)
        ON CONFLICT (id,horario_id) DO NOTHING;
    END LOOP;
EXCEPTION
    WHEN unique_violation THEN
        RAISE NOTICE 'Já existe um assento com o ID % no horário %', id_insere,horario_id_insere ;
    WHEN OTHERS THEN
        RAISE EXCEPTION 'Erro ao inserir assentos: %', SQLERRM;
END;
$$;

INSERT INTO utilizador (
    username,
    password,
    nome,
    genero,
    data_nascimento,
    telefone,
    email
) VALUES (
    'primeiro_administrador',
    '7c82a52267c5a53838a5874962e86e81e9af01f51af585d149733b4b14be1cc2',
    'Administrador',
    'Outro',
    '2000-01-01',
    123456789,
    'admin@example.com'
);

INSERT INTO administrador (
    funcao,
    utilizador_username
) VALUES (
    'Administrador Geral',
    'primeiro_administrador'
);
