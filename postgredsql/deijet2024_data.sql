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
	horario_id			 INTEGER NOT NULL,
	chefe VARCHAR(512),
	utilizador_username		 VARCHAR(512) NOT NULL,
	PRIMARY KEY(utilizador_username)
);

CREATE TABLE administrador (
	funcao				 VARCHAR(512) NOT NULL,
	criado_por VARCHAR(512) NOT NULL,
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

CREATE TABLE passageiro_assento (
	nome		 VARCHAR(512) NOT NULL,
	id			 BIGINT,
	assento_numero	 INTEGER NOT NULL,
	assento_localizacao BOOL NOT NULL,
	voo_id		 INTEGER NOT NULL,
	compra_id		 BIGINT NOT NULL,
	PRIMARY KEY(id)
);

ALTER TABLE cliente ADD CONSTRAINT cliente_fk1 FOREIGN KEY (utilizador_username) REFERENCES utilizador(username);
ALTER TABLE tripulante ADD CONSTRAINT tripulante_fk1 FOREIGN KEY (horario_id) REFERENCES horario(id);
ALTER TABLE tripulante ADD CONSTRAINT tripulante_fk2 FOREIGN KEY (tripulante_utilizador_username) REFERENCES tripulante(utilizador_username);
ALTER TABLE tripulante ADD CONSTRAINT tripulante_fk3 FOREIGN KEY (utilizador_username) REFERENCES utilizador(username);
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
ALTER TABLE horario ADD CONSTRAINT horario_fk1 FOREIGN KEY (voo_id) REFERENCES voo(id);
ALTER TABLE horario ADD CONSTRAINT horario_fk2 FOREIGN KEY (administrador_utilizador_username) REFERENCES administrador(utilizador_username);
ALTER TABLE aeroporto ADD CONSTRAINT aeroporto_fk1 FOREIGN KEY (administrador_utilizador_username) REFERENCES administrador(utilizador_username);
ALTER TABLE passageiro_assento ADD CONSTRAINT passageiro_assento_fk1 FOREIGN KEY (voo_id) REFERENCES voo(id);
ALTER TABLE passageiro_assento ADD CONSTRAINT passageiro_assento_fk2 FOREIGN KEY (compra_id) REFERENCES compra(id);