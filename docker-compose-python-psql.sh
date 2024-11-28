# 
# Sistemas de Gestão de Dados 2024/2025
# Trabalho Prático
#
# Authors: 
#   Diana Martins <dianamartins@student.dei.uc.pt>
#   University of Coimbra


#
# ATTENTION: This will stop and delete all the running containers
# Use it only if you are not using docker for other ativities
#
#docker rm $(docker stop $(docker ps -a -q)) 

mkdir -p python/app/logs

# add  -d  to the command below if you want the containers running in background without logs
docker-compose -f docker-compose-python-psql.yml up --build