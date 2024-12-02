FROM library/postgres


ENV POSTGRES_USER aulaspl
ENV POSTGRES_PASSWORD aulaspl
ENV POSTGRES_DB dbfichas

COPY deijet2024_data.sql /docker-entrypoint-initdb.d/

EXPOSE 5432