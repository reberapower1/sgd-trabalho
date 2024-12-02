/* 
	# 
	# Sistema de Gestão de Dados 2024/2025
	# Trabalho Prático - Deijet
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
	administrador_utilizador_username VARCHAR(512) NOT NULL,
	utilizador_username		 VARCHAR(512) NOT NULL,
	PRIMARY KEY(utilizador_username)
);

CREATE TABLE compra (
	id				 BIGSERIAL,
	data			 TIMESTAMP NOT NULL,
	horario_id			 INTEGER NOT NULL,
	horario_preco		 FLOAT(8) NOT NULL,
	cliente_utilizador_username VARCHAR(512) NOT NULL,
	PRIMARY KEY(id)
);

CREATE TABLE voo (
	capacidade			 INTEGER NOT NULL DEFAULT capacidade > 0,
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
	PRIMARY KEY(id,preco)
);

CREATE TABLE aeroporto (
	nome				 VARCHAR(512) NOT NULL,
	cidade				 VARCHAR(512) NOT NULL,
	pais				 VARCHAR(512) NOT NULL,
	id				 INTEGER,
	administrador_utilizador_username VARCHAR(512) NOT NULL,
	PRIMARY KEY(id)
);

CREATE TABLE bilhete_assento (
	nome			 VARCHAR(512),
	id			 BIGINT,
	assento_id		 VARCHAR(512) NOT NULL,
	assento_localizacao	 BOOL NOT NULL,
	assento_disponibilidade BOOL NOT NULL,
	compra_id		 BIGINT,
	horario_id		 INTEGER NOT NULL,
	horario_preco		 FLOAT(8) NOT NULL,
	PRIMARY KEY(compra_id)
);

CREATE TABLE tripulante_horario (
	tripulante_utilizador_username VARCHAR(512),
	horario_id			 INTEGER,
	horario_preco			 FLOAT(8),
	PRIMARY KEY(tripulante_utilizador_username,horario_id,horario_preco)
);

CREATE TABLE tripulante_tripulante (
	tripulante_utilizador_username	 VARCHAR(512),
	tripulante_utilizador_username1 VARCHAR(512) NOT NULL,
	PRIMARY KEY(tripulante_utilizador_username)
);

ALTER TABLE cliente ADD CONSTRAINT cliente_fk1 FOREIGN KEY (utilizador_username) REFERENCES utilizador(username);
ALTER TABLE tripulante ADD CONSTRAINT tripulante_fk1 FOREIGN KEY (utilizador_username) REFERENCES utilizador(username);
ALTER TABLE administrador ADD CONSTRAINT administrador_fk1 FOREIGN KEY (administrador_utilizador_username) REFERENCES administrador(utilizador_username);
ALTER TABLE administrador ADD CONSTRAINT administrador_fk2 FOREIGN KEY (utilizador_username) REFERENCES utilizador(username);
ALTER TABLE compra ADD CONSTRAINT compra_fk1 FOREIGN KEY (horario_id, horario_preco) REFERENCES horario(id, preco);
ALTER TABLE compra ADD CONSTRAINT compra_fk2 FOREIGN KEY (cliente_utilizador_username) REFERENCES cliente(utilizador_username);
ALTER TABLE voo ADD CONSTRAINT voo_fk1 FOREIGN KEY (administrador_utilizador_username) REFERENCES administrador(utilizador_username);
ALTER TABLE voo ADD CONSTRAINT voo_fk2 FOREIGN KEY (aeroporto_id) REFERENCES aeroporto(id);
ALTER TABLE voo ADD CONSTRAINT voo_fk3 FOREIGN KEY (aeroporto_id1) REFERENCES aeroporto(id);
ALTER TABLE pagamento ADD CONSTRAINT pagamento_fk1 FOREIGN KEY (compra_id) REFERENCES compra(id);
ALTER TABLE pagamento_mbway ADD CONSTRAINT pagamento_mbway_fk1 FOREIGN KEY (pagamento_id) REFERENCES pagamento(id);
ALTER TABLE pagamento_credito ADD CONSTRAINT pagamento_credito_fk1 FOREIGN KEY (pagamento_id) REFERENCES pagamento(id);
ALTER TABLE pagamento_debito ADD CONSTRAINT pagamento_debito_fk1 FOREIGN KEY (pagamento_id) REFERENCES pagamento(id);
ALTER TABLE horario ADD CONSTRAINT horario_fk1 FOREIGN KEY (voo_id) REFERENCES voo(id);
ALTER TABLE horario ADD CONSTRAINT horario_fk2 FOREIGN KEY (administrador_utilizador_username) REFERENCES administrador(utilizador_username);
ALTER TABLE aeroporto ADD CONSTRAINT aeroporto_fk1 FOREIGN KEY (administrador_utilizador_username) REFERENCES administrador(utilizador_username);
ALTER TABLE bilhete_assento ADD UNIQUE (id, assento_id);
ALTER TABLE bilhete_assento ADD CONSTRAINT bilhete_assento_fk1 FOREIGN KEY (compra_id) REFERENCES compra(id);
ALTER TABLE bilhete_assento ADD CONSTRAINT bilhete_assento_fk2 FOREIGN KEY (horario_id, horario_preco) REFERENCES horario(id, preco);
ALTER TABLE tripulante_horario ADD CONSTRAINT tripulante_horario_fk1 FOREIGN KEY (tripulante_utilizador_username) REFERENCES tripulante(utilizador_username);
ALTER TABLE tripulante_horario ADD CONSTRAINT tripulante_horario_fk2 FOREIGN KEY (horario_id, horario_preco) REFERENCES horario(id, preco);
ALTER TABLE tripulante_tripulante ADD CONSTRAINT tripulante_tripulante_fk1 FOREIGN KEY (tripulante_utilizador_username) REFERENCES tripulante(utilizador_username);
ALTER TABLE tripulante_tripulante ADD CONSTRAINT tripulante_tripulante_fk2 FOREIGN KEY (tripulante_utilizador_username1) REFERENCES tripulante(utilizador_username);



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
    -- Insere os dados na tabela utilizador
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

CREATE OR REPLACE PROCEDURE addAdmin( username utilizador.username%type,
    password  utilizador.password%type,
    nome        utilizador.nome%type,
    genero      utilizador.genero%type,
    data_nascimento utilizador.data_nascimento%type,
    telefone    utilizador.telefone%type,
    email       utilizador.email%type,
	funcao		administrador.funcao%type,
	administrador_utilizador_username administrador.administrador_utilizador_username%type
	)
LANGUAGE plpgsql
AS $$
BEGIN
	call addUtilizador(username, password, nome, genero, data_nascimento, telefone, email);
	INSERT INTO administrador(utilizador_username, funcao, administrador_utilizador_username)
	VALUES (username, funcao, administrador_utilizador_username);
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
	funcao		tripulante.funcao%type,
	tripulante_utilizador_username tripulante.tripulante_utilizador_username%type
	)
LANGUAGE plpgsql
AS $$
BEGIN
	call addUtilizador(username, password, nome, genero, data_nascimento, telefone, email);
	INSERT INTO tripulante(utilizador_username, funcao, tripulante_utilizador_username)
	VALUES (username, funcao, tripulante_utilizador_username);
EXCEPTION
    WHEN foreign_key_violation THEN
        RAISE EXCEPTION 'Erro: O username não existe na tabela utilizador.';
    WHEN unique_violation THEN
        RAISE EXCEPTION 'Erro: O tripulante já está registado.';
    WHEN others THEN
        RAISE EXCEPTION 'Erro inesperado: %', SQLERRM;

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
    preco horario.preco%type
	voo_id horario.voo_id%type,
	administrador_utilizador_username horario.administrador_utilizador_username%type 
)
LANGUAGE plpgsql
AS $$
BEGIN
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
RETURNS SETOF bilhete_assento.assento_id%type AS $$
BEGIN
    RETURN (
        SELECT assento_id
        FROM bilhete_assento
        JOIN horario ON bilhete_assento.horario_id = horario.id
        JOIN voo ON horario.voo_id = voo.id
		WHERE voo_id_check = voo.id and horario_id_check = horario.id and assento_disponibilidade = true
    );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION top_destinations(n INTEGER)
RETURNS TABLE (
    destination_airport aeroporto.id%type,
    number_flights INTEGER
) 
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        voo.aeroporto_destino AS destination_airport,
        COUNT(horario.id) AS number_flights
    FROM 
        voo
    JOIN 
        horario ON voo.id = horario.voo_id
    WHERE 
        horario.partida >= date_trunc('month', CURRENT_DATE) - interval '12 months'
    GROUP BY 
        voo.aeroporto_destino
    ORDER BY 
        number_flights DESC
    LIMIT 
        n;
END;
$$;

CREATE OR REPLACE FUNCTION top_routes_per_month(n INTEGER)
RETURNS TABLE (
    month TEXT,
    topN JSONB
)
LANGUAGE plpgsql
AS $$
DECLARE
    month_record RECORD;
BEGIN
    -- Utiliza um loop para iterar sobre cada mês dos últimos 12 meses
    FOR month_record IN
        SELECT TO_CHAR(h.partida, 'Month_YYYY') AS month
        FROM horario h
        WHERE h.partida >= CURRENT_DATE - INTERVAL '12 months'
        GROUP BY month
        ORDER BY month DESC
    LOOP
        RETURN QUERY
        SELECT
            month_record.month AS month,
            JSONB_AGG(
                JSONB_BUILD_OBJECT(
                    'flight_id', v.id,
                    'total_passengers', COUNT(b.id)
                )
            ) AS topN
        FROM
            bilhete_assento b
        JOIN
            horario h ON b.horario_id = h.id
        JOIN
            voo v ON h.voo_id = v.id
        WHERE
            b.assento_disponibilidade = FALSE
            AND TO_CHAR(h.partida, 'Month_YYYY') = month_record.month
        GROUP BY
            v.id, month_record.month
        ORDER BY
            COUNT(b.id) DESC
        LIMIT n;
    END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION get_top_routes_last_12_months(n INTEGER)
RETURNS TABLE (
    month TEXT,
    flight_id INTEGER,
    total_passengers INTEGER
)
LANGUAGE sql
AS $$
SELECT
    TO_CHAR(horario.partida, 'Month_YYYY') AS month,
    voo.id AS flight_id,
    COUNT(bilhete_assento.id) AS total_passengers
FROM
    bilhete_assento
JOIN
    horario ON bilhete_assento.horario_id = horario.id
JOIN
    voo ON horario.voo_id = voo.id
WHERE
    bilhete_assento.assento_disponibilidade = FALSE
    AND horario.partida >= CURRENT_DATE - INTERVAL '12 months'
GROUP BY
    TO_CHAR(horario.partida, 'Month_YYYY'), voo.id
ORDER BY
    month,
    total_passengers DESC
LIMIT n;
$$;
