/* 
	# 
	# Sistema de Gestão de Dados 2024/2025
	# Trabalho Prático - Deijet
	#
*/

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
	id aeroporto.id%type	
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
	preco voo.preco%type,
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
    INSERT INTO voo (preco, capacidade, id, administrador_utilizador_username, aeroporto_origem, aeroporto_destino)
    VALUES (preco, capacidade, id, administrador_utilizador_username, aeroporto_origem, aeroporto_destino);

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
	voo_id horario.voo_id%type,
	administrador_utilizador_username horario.administrador_utilizador_username%type 
)
LANGUAGE plpgsql
AS $$
BEGIN
    -- Insere os dados na tabela utilizador
    INSERT INTO horario (partida,chegada,id, voo_id,administrador_utilizador_username)
    VALUES (partida,chegada,id, voo_id,administrador_utilizador_username);

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
RETURNS bilhete_assento.assento_id%type[] AS $$
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







CREATE OR REPLACE PROCEDURE addCompra(
    voo_check voo.id%type,
    horario_check horario.id%type,
    assento_check bilhete_assento.assento_id%type
)
LANGUAGE plpgsql
AS $$
DECLARE
    compra_id compra.id%type;
    preco_voo voo.preco%type;
    assento_disponivel bilhete_assento.assento_disponibilidade%type
BEGIN
    
    -- Obter o preço do voo
    SELECT preco
    INTO preco_voo
    FROM voo
    WHERE voo.id = voo_check;

    -- Verificar se o assento está disponível para o horário especificado
    SELECT assento_disponibilidade
    INTO assento_disponivel
    FROM bilhete_assento
    WHERE bilhete_assento.horario_id = horario_check AND bilhete_assento.assento_id = assento_check
    FOR UPDATE;

    -- Verificar se o assento ainda está disponível após o bloqueio
    IF NOT EXISTS (
        SELECT 1
        FROM bilhete_assento
        WHERE bilhete_assento.horario_id = horario_check
		and bilhete_assento.assento_id = assento_check 
		AND bilhete_assento.assento_disponibilidade = true
    ) THEN
        RAISE EXCEPTION 'Assento não disponível.';
    END IF;

    -- Inserir a reserva na tabela compra
    INSERT INTO compra (id, data, preco, horario_id, cliente_utilizador_username)
    VALUES ( id, data, preco_voo, horario_id, cliente_utilizador_username )
    RETURNING id INTO compra_id;

    -- Atualizar a tabela bilhete_assento para marcar o assento como reservado
    UPDATE bilhete_assento
    SET bilhete_assento.compra_id = compra_id, assento_disponibilidade = FALSE
    WHERE compra.horario_id = bilhete_assento.horario_id AND bilhete_assento.assento_id = assento_check;

    -- Commit da transação (implícito no final do procedimento)
END;
$$;
