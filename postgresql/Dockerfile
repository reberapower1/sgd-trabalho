FROM library/postgres


ENV POSTGRES_USER deijet
ENV POSTGRES_PASSWORD tapsocialista
ENV POSTGRES_DB db_deijet

COPY deijet2024_data.sql /docker-entrypoint-initdb.d/

EXPOSE 5432