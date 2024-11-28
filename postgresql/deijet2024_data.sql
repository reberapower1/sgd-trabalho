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
	funcao			 VARCHAR(512) NOT NULL,
	tripulante_utilizador_username VARCHAR(512) NOT NULL,
	utilizador_username		 VARCHAR(512) NOT NULL,
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
	ultima_atualizacao		 TIMESTAMP NOT NULL,
	preco			 FLOAT(8) NOT NULL,
	formas_pagamento		 VARCHAR(512) NOT NULL,
	estado_reserva		 VARCHAR(512) NOT NULL,
	horario_id			 INTEGER NOT NULL,
	cliente_utilizador_username VARCHAR(512) NOT NULL,
	PRIMARY KEY(id)
);

CREATE TABLE voo (
	preco				 FLOAT(8) NOT NULL,
	capacidade			 INTEGER NOT NULL,
	id				 INTEGER,
	administrador_utilizador_username VARCHAR(512) NOT NULL,
	aeroporto_id			 INTEGER NOT NULL,
	aeroporto_id1			 INTEGER NOT NULL,
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
	pagamento_id BIGINT NOT NULL,
	PRIMARY KEY(id)
);

CREATE TABLE pagamento_credito (
	id		 BIGSERIAL,
	valor	 FLOAT(8) NOT NULL,
	n_conta	 BIGINT NOT NULL,
	pagamento_id BIGINT NOT NULL,
	PRIMARY KEY(id)
);

CREATE TABLE pagamento_debito (
	n_conta	 BIGINT NOT NULL,
	valor	 FLOAT(8) NOT NULL,
	id		 BIGSERIAL NOT NULL,
	pagamento_id BIGINT NOT NULL,
	PRIMARY KEY(id)
);

CREATE TABLE horario (
	partida				 TIMESTAMP NOT NULL,
	duracao				 TIMESTAMP,
	id				 INTEGER,
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

CREATE TABLE passageiro_assento (
	nome		 VARCHAR(512) NOT NULL,
	id			 BIGINT,
	assento_numero	 INTEGER NOT NULL,
	assento_localizacao BOOL NOT NULL,
	voo_id		 INTEGER NOT NULL,
	compra_id		 BIGINT NOT NULL,
	PRIMARY KEY(id)
);

CREATE TABLE tripulante_horario (
	tripulante_utilizador_username VARCHAR(512),
	horario_id			 INTEGER,
	PRIMARY KEY(tripulante_utilizador_username,horario_id)
);

CREATE TABLE horario_voo (
	horario_id INTEGER,
	voo_id	 INTEGER,
	PRIMARY KEY(horario_id,voo_id)
);

ALTER TABLE cliente ADD CONSTRAINT cliente_fk1 FOREIGN KEY (utilizador_username) REFERENCES utilizador(username);
ALTER TABLE tripulante ADD CONSTRAINT tripulante_fk1 FOREIGN KEY (tripulante_utilizador_username) REFERENCES tripulante(utilizador_username);
ALTER TABLE tripulante ADD CONSTRAINT tripulante_fk2 FOREIGN KEY (utilizador_username) REFERENCES utilizador(username);
ALTER TABLE administrador ADD CONSTRAINT administrador_fk1 FOREIGN KEY (administrador_utilizador_username) REFERENCES administrador(utilizador_username);
ALTER TABLE administrador ADD CONSTRAINT administrador_fk2 FOREIGN KEY (utilizador_username) REFERENCES utilizador(username);
ALTER TABLE compra ADD CONSTRAINT compra_fk1 FOREIGN KEY (horario_id) REFERENCES horario(id);
ALTER TABLE compra ADD CONSTRAINT compra_fk2 FOREIGN KEY (cliente_utilizador_username) REFERENCES cliente(utilizador_username);
ALTER TABLE voo ADD CONSTRAINT voo_fk1 FOREIGN KEY (administrador_utilizador_username) REFERENCES administrador(utilizador_username);
ALTER TABLE voo ADD CONSTRAINT voo_fk2 FOREIGN KEY (aeroporto_id) REFERENCES aeroporto(id);
ALTER TABLE voo ADD CONSTRAINT voo_fk3 FOREIGN KEY (aeroporto_id1) REFERENCES aeroporto(id);
ALTER TABLE pagamento ADD CONSTRAINT pagamento_fk1 FOREIGN KEY (compra_id) REFERENCES compra(id);
ALTER TABLE pagamento_mbway ADD CONSTRAINT pagamento_mbway_fk1 FOREIGN KEY (pagamento_id) REFERENCES pagamento(id);
ALTER TABLE pagamento_credito ADD CONSTRAINT pagamento_credito_fk1 FOREIGN KEY (pagamento_id) REFERENCES pagamento(id);
ALTER TABLE pagamento_debito ADD CONSTRAINT pagamento_debito_fk1 FOREIGN KEY (pagamento_id) REFERENCES pagamento(id);
ALTER TABLE horario ADD CONSTRAINT horario_fk1 FOREIGN KEY (administrador_utilizador_username) REFERENCES administrador(utilizador_username);
ALTER TABLE aeroporto ADD CONSTRAINT aeroporto_fk1 FOREIGN KEY (administrador_utilizador_username) REFERENCES administrador(utilizador_username);
ALTER TABLE passageiro_assento ADD CONSTRAINT passageiro_assento_fk1 FOREIGN KEY (voo_id) REFERENCES voo(id);
ALTER TABLE passageiro_assento ADD CONSTRAINT passageiro_assento_fk2 FOREIGN KEY (compra_id) REFERENCES compra(id);
ALTER TABLE tripulante_horario ADD CONSTRAINT tripulante_horario_fk1 FOREIGN KEY (tripulante_utilizador_username) REFERENCES tripulante(utilizador_username);
ALTER TABLE tripulante_horario ADD CONSTRAINT tripulante_horario_fk2 FOREIGN KEY (horario_id) REFERENCES horario(id);
ALTER TABLE horario_voo ADD CONSTRAINT horario_voo_fk1 FOREIGN KEY (horario_id) REFERENCES horario(id);
ALTER TABLE horario_voo ADD CONSTRAINT horario_voo_fk2 FOREIGN KEY (voo_id) REFERENCES voo(id);

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
    email       utilizador.email%type
	funcao		administrador.funcao%type,
	administrador_utilizador_username administrador_utilizador_username.administrador_utilizador_username%type,
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
    email       utilizador.email%type
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
DECLARE tipo_user integer; verificar_user utilizador.username%type;
BEGIN
    SELECT username
	INTO verificar_user
	FROM utilizador
	WHERE utilizador.username = username_login AND utilizador.password = password_login;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Username ou password errados';
    END IF;

    IF EXISTS (SELECT 1 FROM cliente WHERE cliente.utilizador_username = ) THEN
		:= 1;
    ELSIF EXISTS (SELECT 1 FROM tripulante WHERE contract_employee_person_cc = resultado.current_person_cc) THEN
        resultado.type := 2;
    ELSIF EXISTS (SELECT 1 FROM administrador WHERE employee_cc = resultado.current_person_cc) THEN
        resultado.type := 3;
    END IF;

    RETURN resultado;
END;
$$ LANGUAGE plpgsql;
